"""Scan budget: the guarantee that run() always terminates.

Two independent caps: a wall-clock deadline and a max request count. Every
HTTP send goes through spend_request() first, so the scanner can never exceed
either bound. Exhaustion raises BudgetExceeded; the engine catches it and
finishes the scan as DONE_PARTIAL with results kept.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from .errors import BudgetExceeded


@dataclass
class ScanBudget:
    """Immutable budget limits for a scan."""
    deadline_s: float
    max_requests: int


class Budget:
    """Live budget tracker. One per scan."""

    def __init__(self, limits: ScanBudget, clock: callable = time.monotonic):
        self._limits = limits
        self._clock = clock
        self._start = clock()
        self.requests_sent = 0

    @property
    def elapsed_s(self) -> float:
        return self._clock() - self._start

    @property
    def remaining_s(self) -> float:
        return max(0.0, self._limits.deadline_s - self.elapsed_s)

    @property
    def expired(self) -> bool:
        return (self.remaining_s <= 0.0
                or self.requests_sent >= self._limits.max_requests)

    def reason(self) -> str:
        if self.requests_sent >= self._limits.max_requests:
            return f"request cap reached ({self._limits.max_requests})"
        return f"time deadline reached ({self._limits.deadline_s:.0f}s)"

    def spend_request(self) -> None:
        """Account one request. Raises BudgetExceeded if no budget remains."""
        if self.expired:
            raise BudgetExceeded(self.reason())
        self.requests_sent += 1
