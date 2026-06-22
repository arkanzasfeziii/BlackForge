"""Secret pattern scanner for detecting leaked credentials in text."""

from __future__ import annotations

import re
from typing import Dict, List

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY"),
    (r"AIza[0-9A-Za-z\-_]{35}", "GOOGLE_API_KEY"),
    (r"ghp_[0-9a-zA-Z]{36}", "GITHUB_PAT"),
    (r"glpat-[0-9a-zA-Z\-_]{20}", "GITLAB_PAT"),
    (r"sk-[a-zA-Z0-9]{48}", "OPENAI_KEY"),
    (r"(?i)password\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", "PASSWORD"),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_\.]{20,})", "API_KEY"),
    (r"(?i)(secret|token)\s*[:=]\s*['\"]([^\s'\"]{16,})['\"]", "SECRET"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "PRIVATE_KEY"),
    (r"(?i)connectionString\s*=\s*\"([^\"]+)\"", "CONNECTION_STRING"),
    (r"(?i)(access[_-]?token|bearer)\s*[:=]\s*['\"]([^\s'\"]{20,})['\"]", "ACCESS_TOKEN"),
]


def scan_secrets(text: str) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, str(text), re.MULTILINE | re.DOTALL):
            val = m.group(0) if not m.groups() else (m.group(1) or m.group(0))
            if len(val) > 200:
                val = val[:200]
            found.append({"type": label, "value": val})
    return found
