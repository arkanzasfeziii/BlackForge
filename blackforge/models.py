"""Data models used across all BlackForge modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class AttackResult:
    module: str
    action: str
    status: str
    target: str = ""
    data: Any = None
    severity: str = "INFO"
    notes: str = ""


@dataclass
class Credential:
    type: str
    value: Dict[str, str]
    source: str
    notes: str = ""


@dataclass
class EngagementContext:
    results: List[AttackResult] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    loot: Dict[str, Any] = field(default_factory=dict)
    delay: float = 0.5
    session: Optional[Any] = None

    def __post_init__(self) -> None:
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.verify = False
