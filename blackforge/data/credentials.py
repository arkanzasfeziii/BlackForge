"""Default credential lists for CI/CD platforms and artifact registries."""

from __future__ import annotations

from typing import Dict, List, Tuple

ARGOCD_DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "argocd"),
    ("admin", "Admin123"),
    ("root", "root"),
]

ARTIFACT_DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "Admin1234"),
    ("admin", "Nexus1234"),
    ("admin", "Harbor12345"),
    ("root", "root"),
]
