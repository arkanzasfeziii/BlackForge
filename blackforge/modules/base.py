"""Abstract base class for all attack modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from blackforge.models import AttackResult, EngagementContext


class BaseModule(ABC):
    """Every attack module must implement the run() method."""

    name: str = "base"

    @abstractmethod
    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        ...
