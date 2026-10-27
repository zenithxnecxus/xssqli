"""Detector registry.

build_detectors(config) returns every detector the engine will run, in the
order they are tried for a given parameter. Cheaper/more-certain checks
(SQLi, XSS) run before the two new scanners (Open Redirect, SSTI) so the
engine's per-parameter early-stop (confidence >= early_stop_confidence) can
skip the rest once a high-confidence hit is already in hand.
"""
from __future__ import annotations

from ..models import ScanConfig
from .base import Detector
from .openredirect import OpenRedirectDetector
from .sqli import SQLiDetector
from .ssti import SSTIDetector
from .xss import XSSDetector

__all__ = ["Detector", "SQLiDetector", "XSSDetector", "OpenRedirectDetector",
          "SSTIDetector", "build_detectors"]


def build_detectors(config: ScanConfig) -> list[Detector]:
    return [
        SQLiDetector(config),
        XSSDetector(config),
        OpenRedirectDetector(config),
        SSTIDetector(config),
    ]
