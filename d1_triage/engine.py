"""LiquidAI d1-3B Alert Triage Engine."""
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from d1_triage.sink_finder import build_annotated_prompt, find_sink_line

MODEL_NAME = "LiquidAI/d1-3B"

TRIAGE_QUESTION = (
    "Is this static-analysis warning a real, exploitable security bug at the flagged sink (marked with >>>) in the code below? "
    "Answer yes only if untrusted input reaches this specific sink without an effective guard."
)

TRIAGE_CRITERIA = {
    "true": "Untrusted input reaches the flagged sink marked with '>>>', and no effective validation, escaping, or containment check neutralizes it in the code.",
    "false": "The flagged sink is protected by guards/validation, input is from a trusted or static source, or the pattern is safe or style-only.",
}

QUESTIONS = {
    "tp": {
        "type": "noul",
        "instructions": TRIAGE_QUESTION,
        "criteria": TRIAGE_CRITERIA,
    }
}


@dataclass
class TriageFinding:
    id: str
    rule: str
    cwe: str
    file_path: str
    line_number: int
    code_window: str
    message: str = ""
    ground_truth: Optional[str] = None


@dataclass
class TriageResult:
    finding_id: str
    rule: str
    cwe: str
    file_path: str
    line_number: int
    decision: str  # "TRUE POSITIVE" or "FALSE POSITIVE"
    is_exploitable: bool
    p_tp: float
    confidence_pct: float
    sink_statement: str
    latency_ms: float
    device: str
    explanation: str = ""
    ground_truth: Optional[str] = None


def generate_explanation(finding: TriageFinding, is_exploitable: bool, sink_stmt: str) -> str:
    """Generate concise 1-sentence developer remediation or false-positive rationale."""
    rule_lower = finding.rule.lower()
    cwe_lower = finding.cwe.lower()

    if "path-traversal" in rule_lower or "cwe-22" in cwe_lower:
        if is_exploitable:
            return f"Untrusted input reaches filesystem sink ('{sink_stmt}') without verifying canonical path containment (getCanonicalPath().startsWith(baseDir))."
        return f"Path sink ('{sink_stmt}') is protected by directory containment or resolves against a sanitized path."

    if "documentbuilder" in rule_lower or "xxe" in rule_lower or "cwe-611" in cwe_lower:
        if is_exploitable:
            return f"XML parser initialized at '{sink_stmt}' without enabling FEATURE_SECURE_PROCESSING or disallowing external DTDs."
        return f"XML parser at '{sink_stmt}' explicitly enforces secure processing features, neutralizing external entity expansion."

    if "sql" in rule_lower or "cwe-89" in cwe_lower:
        if is_exploitable:
            return f"Dynamic SQL query constructed at '{sink_stmt}' without parameterized PreparedStatement binding."
        return f"SQL query at '{sink_stmt}' uses parameterized positional placeholders or fixed constant statements."

    if "deserialization" in rule_lower or "cwe-502" in cwe_lower:
        if is_exploitable:
            return f"Untrusted stream decoded at '{sink_stmt}' without ClassFilter gadget inspection."
        return f"Deserialization at '{sink_stmt}' is guarded by class whitelisting or operates on trusted input."

    if "socket" in rule_lower or "unencrypted" in rule_lower:
        if is_exploitable:
            return f"Plaintext network socket created at '{sink_stmt}' without TLS encryption (SSLSocket)."
        return f"Network socket at '{sink_stmt}' operates on localhost loopback or is wrapped in TLS."

    # Generic Fallback
    if is_exploitable:
        return f"Exploitable security sink detected at line {finding.line_number} ('{sink_stmt}') without neutralizing guards."
    return f"Safe pattern: flagged sink at line {finding.line_number} is neutralized by defensive validation or static context."


class D1TriageEngine:
    def __init__(self, model_name: str = MODEL_NAME, device: Optional[str] = None, mock: bool = False, explain: bool = True):
        self.model_name = model_name
        self.mock = mock
        self.explain = explain
        self.model = None
        self.tokenizer = None
        self._device = device

    @property
    def device(self) -> str:
        if self._device:
            return self._device
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"

    def load(self):
        """Lazy load the d1-3B model on target device (CPU or CUDA)."""
        if self.mock or self.model is not None:
            return

        import torch
        from transformers import AutoModel, AutoTokenizer

        target_device = self.device
        dtype = torch.float16 if target_device == "cuda" else torch.float32

        print(f"Loading {self.model_name} on {target_device.upper()} ({dtype})...", file=sys.stderr)
        t0 = time.time()
        self.model = AutoModel.from_pretrained(
            self.model_name,
            trust_remote_code=True,
            torch_dtype=dtype,
        ).to(target_device)
        self.model.eval()
        print(f"Model loaded in {time.time() - t0:.1f}s", file=sys.stderr)

    def triage_one(self, finding: TriageFinding, threshold: float = 0.5) -> TriageResult:
        """Triage a single finding through d1-3B with statement-level sink grounding."""
        sink_idx, sink_stmt = find_sink_line(finding.code_window, finding.rule)
        state_text = build_annotated_prompt(
            code_window=finding.code_window,
            rule=finding.rule,
            cwe=finding.cwe,
            line_no=finding.line_number,
            file_path=finding.file_path,
            message=finding.message,
        )

        t0 = time.time()

        if self.mock:
            # Deterministic mock calculation for fast integration tests
            import hashlib
            seed_int = int(hashlib.md5(f"{finding.rule}:{finding.code_window[:100]}".encode()).hexdigest()[:6], 16)
            p_tp = (seed_int % 1000) / 1000.0
            time.sleep(0.01)
        else:
            self.load()
            import torch
            with torch.inference_mode():
                answers = self.model.system_one_batch([(state_text, QUESTIONS)])
            p_tp = float(answers[0]["answers"]["tp"]["noul"])

        elapsed_ms = (time.time() - t0) * 1000.0
        is_tp = p_tp >= threshold
        decision = "TRUE POSITIVE" if is_tp else "FALSE POSITIVE"
        conf = max(p_tp, 1.0 - p_tp) * 100.0

        explanation = generate_explanation(finding, is_tp, sink_stmt) if self.explain else ""

        return TriageResult(
            finding_id=finding.id,
            rule=finding.rule,
            cwe=finding.cwe,
            file_path=finding.file_path,
            line_number=finding.line_number,
            decision=decision,
            is_exploitable=is_tp,
            p_tp=round(p_tp, 4),
            confidence_pct=round(conf, 1),
            sink_statement=sink_stmt,
            latency_ms=round(elapsed_ms, 1),
            device=self.device,
            explanation=explanation,
            ground_truth=finding.ground_truth,
        )

    def triage_batch(self, findings: List[TriageFinding], threshold: float = 0.5) -> List[TriageResult]:
        """Triage a batch of findings."""
        return [self.triage_one(f, threshold=threshold) for f in findings]
