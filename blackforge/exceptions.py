"""Custom exception hierarchy for BlackForge."""

from __future__ import annotations


class BlackForgeError(Exception):
    """Base exception for all BlackForge errors."""


class ModuleError(BlackForgeError):
    """Raised when a module encounters a runtime error."""


class AuthenticationError(BlackForgeError):
    """Raised when authentication fails against a target."""


class ConnectionError(BlackForgeError):
    """Raised when a connection to a target cannot be established."""


class DependencyError(BlackForgeError):
    """Raised when a required dependency is missing."""

    def __init__(self, package: str) -> None:
        super().__init__(f"Missing required package: {package}. Install with: pip install {package}")
        self.package = package
