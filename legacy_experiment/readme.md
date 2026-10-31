# Legacy experiment - superseded

This folder holds the first version of the project, before TriageMate. It is kept for provenance only and is not part of the current release.

## What changed

The old experiment trained a binary classifier on a dataset with serious label leaks: class names like `PathTraversalVulnerability`, comments stating the verdict, and ~30% duplicate rows. The reported 97.9% accuracy was mostly name reading.

The current `triage/` and `training/` code rebuilds the dataset with per-row neutralization (method names flipped randomly per row), holds out five CWE families the model never trains on, and evaluates with precision/recall/F1/ROC-AUC/ECE instead of raw accuracy.

See `notes/leak-audit.md` for the full leak audit and `README.md` for the current results.

## Contents

- `finetuning/` - old finetuning notebook
- `misc/` - old eval scripts and results
- `java_eval_new.ipynb` - old evaluation notebook
