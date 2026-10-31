"""Statement-level sink finder for static analysis alert triage."""
import re
from typing import List, Optional, Tuple

RULE_PATTERNS = {
    'documentbuilderfactory': [r'DocumentBuilderFactory', r'DocumentBuilder', r'getDocBuilder', r'parserFactory', r'builderFactory'],
    'transformerfactory': [r'TransformerFactory', r'Transformer', r'newTransformer'],
    'saxparserfactory': [r'SAXParserFactory', r'newSAXParser', r'SAXParser'],
    'path-traversal': [r'new\s+File\b', r'Paths\.get\b', r'getResource\b', r'FileInputStream\b', r'openStream\b', r'getRequestedFile\b', r'File\b'],
    'formatted-sql-string': [r'String\.format\b', r'createQuery\b', r'prepareStatement\b', r'SELECT\b', r'execute\b', r'\+'],
    'object-deserialization': [r'new\s+ObjectInputStream\b', r'\.readObject\b', r'ObjectInputStream\b', r'readUnshared\b', r'resolveClass\b'],
    'unrestricted-request-mapping': [r'@RequestMapping\b', r'@GetMapping\b', r'@PostMapping\b'],
    'unencrypted-socket': [r'new\s+ServerSocket\b', r'new\s+Socket\b', r'ServerSocket\b'],
    'cookie-missing-httponly': [r'setHttpOnly\b', r'new\s+Cookie\b', r'Cookie\b'],
    'cookie-missing-secure-flag': [r'setSecure\b', r'new\s+Cookie\b', r'Cookie\b'],
    'script-engine-injection': [r'\.eval\(', r'ScriptEngine\b'],
    'use-of-md5': [r'MessageDigest\.getInstance', r'MD5', r'md5\b'],
    'use-of-sha1': [r'MessageDigest\.getInstance', r'SHA-1', r'sha1\b'],
    'url-rewriting': [r'encodeURL\b', r'encodeRedirectURL\b', r'response\.encodeURL\b', r'FormAuthenticator\b', r'getSession\b'],
    'el-injection': [r'ExpressionFactory\b', r'createValueExpression\b', r'evaluate\b', r'buildConstraintViolationWithTemplate\b', r'interpolate\b'],
    'spel-injection': [r'parseExpression\b', r'SpelExpressionParser\b', r'PARSER\b'],
    'crlf-injection-logs': [r'log\.(info|debug|warn|error)\b', r'logger\.(info|debug|warn|error)\b'],
    'tainted-session-from-http-request': [r'session\.setAttribute\b', r'setAttribute\b'],
}


def find_sink_line(code_window: str, rule_name: str) -> Tuple[int, str]:
    """Find the most likely dangerous sink line index and content within a code window."""
    lines = code_window.splitlines()
    if not lines:
        return 0, ""

    rule_key = rule_name.lower().split('.')[-1]
    patterns = RULE_PATTERNS.get(rule_key, [])

    # Search for pattern match
    for pat in patterns:
        for idx, line in enumerate(lines):
            if re.search(pat, line, re.IGNORECASE):
                return idx, line.strip()

    # Fallback: choose middle non-empty statement
    mid = len(lines) // 2
    for offset in range(len(lines)):
        for candidate in (mid + offset, mid - offset):
            if 0 <= candidate < len(lines):
                s = lines[candidate].strip()
                if s and not s.startswith(("//", "/*", "*", "import", "package", "@")):
                    return candidate, s

    return mid, lines[mid].strip() if mid < len(lines) else ""


def build_annotated_prompt(code_window: str, rule: str, cwe: str, line_no: int,
                           file_path: str = "Target.java", message: str = "") -> str:
    """Format the finding with the statement-level sink marker for d1-3B."""
    sink_idx, sink_stmt = find_sink_line(code_window, rule)
    lines = code_window.splitlines()

    annotated = []
    for idx, l in enumerate(lines):
        if idx == sink_idx:
            annotated.append(f">>> [ALERT LINE {line_no}]: {l}")
        else:
            annotated.append(f"    {l}")

    body = "\n".join(annotated)
    header = [
        f"Rule: {rule}",
        f"CWE: {cwe}",
        f"Severity: WARNING",
        f"File: {file_path.split('/')[-1]}",
        f"Flagged Line: {line_no}",
    ]
    if sink_stmt:
        header.append(f"Flagged Sink Statement: {sink_stmt}")
    if message:
        header.append(f"Rule message: {message}")

    return "\n".join(header) + f"\n\nJava (Flagged sink marked with >>>):\n```java\n{body}\n```"
