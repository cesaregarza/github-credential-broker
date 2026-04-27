from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowRateLimiter:
    def __init__(self, *, window_seconds: int = 60) -> None:
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, deque[float]] = {}

    def allow(self, key: str, *, limit: int, now: float | None = None) -> bool:
        current_time = time.monotonic() if now is None else now
        cutoff = current_time - self._window_seconds
        with self._lock:
            timestamps = self._requests.setdefault(key, deque())
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if len(timestamps) >= limit:
                return False
            timestamps.append(current_time)
            return True
