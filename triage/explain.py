"""Deterministic why and fix text for a triaged alert.

The fix is CWE-level guidance, not a patch. It is not compiled or tested.
"""
from pathlib import Path

FIX_HINTS = {
    "CWE-22": "Resolve the path against a fixed base directory and reject any result that leaves it.",
    "CWE-77": "Build the command with a fixed argument list instead of concatenating untrusted text.",
    "CWE-78": "Use ProcessBuilder with a fixed argument list; never pass untrusted text through a shell.",
    "CWE-74": "Do not build interpreter or XML input from untrusted text; disable DOCTYPE and external entities.",
    "CWE-79": "HTML-escape the value for its output context, or use the framework encoder.",
    "CWE-611": "Disable DOCTYPE declarations and external entities on the XML parser factory before parsing untrusted input.",
}

GENERIC_FIX = "Validate the untrusted input at this sink and reject values that reach it unchanged."


def explain(row, verdict):
    """Return a rule-message explanation and a fix hint only for TP verdicts."""
    message = (row.get("message") or "").strip()
    location = f"{Path(str(row.get('file', '?'))).name}:{row.get('line', 0)}"
    why = message or f"{row.get('rule', 'rule')} flagged {row.get('cwe', 'this sink')} at {location}."
    if verdict != "TP":
        return {"why": why, "fix": ""}
    return {"why": why, "fix": FIX_HINTS.get(row.get("cwe", ""), GENERIC_FIX)}
