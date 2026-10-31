#!/usr/bin/env python
"""Liquid AI d1-3B Static Analysis Alert Triage CLI Tool.

Usage:
    python d1_triage.py --demo                      # Run built-in demo showcase
    python d1_triage.py --scan semgrep.json         # Triage Semgrep scan output
    python d1_triage.py --benchmark ghsa --limit 5  # Triage real benchmark alerts
    python d1_triage.py --cpu                       # Force CPU execution
    python d1_triage.py --mock                      # Integration dry-run without downloading model
"""
from d1_triage.cli import main

if __name__ == "__main__":
    main()
