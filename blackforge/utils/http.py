"""HTTP request wrapper with rate limiting and error handling."""

from __future__ import annotations

import time
from typing import Any, Optional

from blackforge.config import TIMEOUT
from blackforge.models import EngagementContext, HAS_REQUESTS


def request(
    ctx: EngagementContext,
    method: str,
    url: str,
    **kwargs: Any,
) -> Optional[Any]:
    if not HAS_REQUESTS:
        return None
    try:
        time.sleep(ctx.delay)
        return ctx.session.request(
            method, url, timeout=TIMEOUT, allow_redirects=False, **kwargs
        )
    except Exception:
        return None
