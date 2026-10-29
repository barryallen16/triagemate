"""Decision-model scorer for B2/B3: state, one bounded question, typed options.

The shape follows SemIf (formerly OpenJev): the state and the option
descriptions go into one prompt, and the score is read from the option logits
in a single forward pass. No answer sentence is generated, so a decision model
returns no WHY or FIX prose.
"""
from pathlib import Path

from triage.prompts import MAX_CHARS

# Pinned the way SemIf pins its reference run, so scores stay comparable.
MODEL = "Qwen/Qwen3.5-4B"
REVISION = "851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a"

QUESTION = "Is this warning a real exploitable bug in the code above?"
OPTIONS = [
    {"id": "TP", "description": "A real vulnerability: the flagged code can be exploited."},
    {"id": "FP", "description": "Noise: not exploitable here, or the rule misreads this code."},
]


def state_of(row):
    """What a reviewer reads before deciding: the alert and the code it points at."""
    window = row["code_window"]
    if len(window) > MAX_CHARS:
        window = window[:MAX_CHARS] + "\n// ... truncated ..."
    lines = [
        f"Rule: {row['rule']}",
        f"CWE: {row['cwe']}",
        f"Severity: {row.get('severity', 'WARNING')}",
        f"File: {row['file'].split('/')[-1]}",
        f"Line: {row.get('line', 0)}",
    ]
    if row.get("message"):
        lines.append(f"Rule message: {row['message']}")
    return "\n".join(lines) + f"\n\nJava:\n```java\n{window}\n```"


def decision_input(row):
    """One SemIf-shaped decision row."""
    return {
        "id": row.get("id", ""),
        "state": state_of(row),
        "question": QUESTION,
        "options": OPTIONS,
    }


def prompt_of(row):
    """Render one decision as the text a chat template wraps."""
    decision = decision_input(row)
    option_lines = "\n".join(
        f"- {option['id']}: {option['description']}" for option in decision["options"])
    return (f"STATE:\n{decision['state']}\n\n"
            f"QUESTION: {decision['question']}\n\n"
            f"OPTIONS:\n{option_lines}\n\n"
            "Answer with exactly one option id.")


def confidence_of(p_tp):
    """A binary option readout is confident when it leans hard one way."""
    return round(max(p_tp, 1.0 - p_tp), 6)


def option_token_ids(tokenizer):
    """One token per option, or the readout would compare the wrong logits."""
    ids = []
    for option in OPTIONS:
        # Keyword form: Qwen3.5 tokenizers are multimodal processors whose
        # first positional argument means `images`, not text.
        encoded = tokenizer(text=" " + option["id"], add_special_tokens=False).input_ids
        if len(encoded) != 1:
            raise ValueError(
                f"option {option['id']!r} tokenizes to {len(encoded)} tokens in "
                f"{tokenizer.__class__.__name__}; pick labels that are single tokens")
        ids.append(encoded[0])
    return ids


class DecisionScorer:
    """Reads TP/FP option logits in one forward pass."""

    def __init__(self, model_name=MODEL, revision=REVISION, adapter=""):
        import torch
        from unsloth import FastLanguageModel
        self.torch = torch
        self.model, self.tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name, revision=revision or None,
            max_seq_length=8192, dtype=None, load_in_4bit=True)
        if adapter:
            from peft import PeftModel
            self.model = PeftModel.from_pretrained(self.model, adapter)
        FastLanguageModel.for_inference(self.model)
        self.tok_tp, self.tok_fp = option_token_ids(self.tokenizer)

    def score(self, row):
        """Return (p_tp, confidence). Decision models emit no prose."""
        prefix = self.tokenizer.apply_chat_template(
            [{"role": "system", "content": "You decide one bounded question from declared options."},
             {"role": "user", "content": prompt_of(row)}],
            tokenize=False, add_generation_prompt=True) + "VERDICT:"
        ids = self.tokenizer(text=prefix, return_tensors="pt").to(self.model.device)
        with self.torch.no_grad():
            logits = self.model(**ids).logits[0, -1]
            p_tp = self.torch.softmax(
                self.torch.stack([logits[self.tok_tp], logits[self.tok_fp]]), 0)[0].item()
        return p_tp, confidence_of(p_tp)
