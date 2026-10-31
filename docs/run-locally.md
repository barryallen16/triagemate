# Run locally without a Kaggle GPU

The full model scorer needs CUDA, unsloth, and semgrep. If you don't have a GPU,
use the heuristic scorer instead - it ranks Semgrep alerts by severity and needs
only Python and Java.

## Heuristic scorer (no GPU)

```bash
uv venv
uv sync
uv tool install semgrep   # or: pipx install semgrep

uv run triagemate path/to/java/project --scorer heuristic --json
```

Output is JSONL with `p_tp`, `why`, and `fix` fields. The model is not used, so
this works on any machine.

## Full model scorer (needs CUDA)

```bash
uv sync --extra model
uv run triagemate path/to/java/project \
    --adapter path/to/adapter \
    --json
```

The adapter is published at
[barryallen16/triagemate/qlora-adapter.zip](https://huggingface.co/datasets/barryallen16/triagemate/resolve/main/qlora-adapter.zip).

## Docker

Build once, run anywhere:

```bash
docker build -t triagemate .
docker run --rm -v $(pwd)/my-java-project:/src triagemate \
    /src --scorer heuristic --json
```
