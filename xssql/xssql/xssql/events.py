"""Typed progress events emitted by the engine (DESIGN_DOC_V2 §9).

The engine emits events; callers (CLI logger, future streaming UI) subscribe.
Keeping this as a frozen dataclass means the engine never couples to any
particular consumer.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Callable


class EventType(str, enum.Enum):
    SCAN_STARTED = "scan_started"
    PHASE = "phase"                  # e.g. phase=crawl / phase=detect
    PAGE_CRAWLED = "page_crawled"
    ENDPOINT_FOUND = "endpoint_found"
    ENDPOINT_TESTED = "endpoint_tested"
    FINDING = "finding"
    BUDGET_WARNING = "budget_warning"
    SCAN_FINISHED = "scan_finished"


@dataclass(frozen=True)
class ScanEvent:
    type: EventType
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


EventCallback = Callable[[ScanEvent], None]


def null_callback(_event: ScanEvent) -> None:
    """Default no-op sink."""
    return None
