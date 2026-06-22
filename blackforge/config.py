"""Constants and configuration for BlackForge."""

from __future__ import annotations

from blackforge import __version__, __author__

TOOL_NAME = "BlackForge Framework"
VERSION = __version__
AUTHOR = __author__
COMMAND = "blackforge"

GITHUB_API = "https://api.github.com"
TIMEOUT = 15
DEFAULT_DELAY = 0.5

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║        ⚠   BLACKFORGE — AUTHORIZED RED TEAM USE ONLY   ⚠                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL CI/CD attacks: GitHub Actions secret theft,   ║
║  Jenkins Groovy RCE, GitLab pipeline injection, ArgoCD compromise, artifact ║
║  repository credential harvest, and supply chain dependency confusion.      ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (repos / CI platforms / registries)                      ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
