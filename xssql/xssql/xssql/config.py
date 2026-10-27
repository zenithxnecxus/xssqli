"""Config loading and validation (DESIGN_DOC_V2 §6.2, v1.1 rules).

validate_config enforces every bound; each violated rule raises ConfigError
with a precise message. load_config_from_dict / _from_cli build a ScanConfig.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .errors import ConfigError
from .models import ScanConfig


# (field, predicate(value)->bool valid, message)
_RULES = [
    ("max_depth", lambda v: isinstance(v, int) and 0 <= v <= 10,
     "max_depth must be an int in [0, 10]"),
    ("max_pages", lambda v: isinstance(v, int) and 1 <= v <= 1000,
     "max_pages must be an int in [1, 1000]"),
    ("rate_limit_rps", lambda v: isinstance(v, (int, float)) and 0 < v <= 100,
     "rate_limit_rps must be in (0, 100]"),
    ("request_timeout_s", lambda v: isinstance(v, (int, float)) and 0 < v <= 120,
     "request_timeout_s must be in (0, 120]"),
    ("max_response_bytes", lambda v: isinstance(v, int) and 1024 <= v <= 10 * 1024 * 1024,
     "max_response_bytes must be in [1KB, 10MB]"),
    ("scan_deadline_s", lambda v: isinstance(v, (int, float)) and 1 <= v <= 3600,
     "scan_deadline_s must be in [1, 3600]"),
    ("max_requests", lambda v: isinstance(v, int) and 1 <= v <= 100000,
     "max_requests must be in [1, 100000]"),
    ("max_payloads_per_param", lambda v: isinstance(v, int) and 1 <= v <= 200,
     "max_payloads_per_param must be in [1, 200]"),
    ("boolean_threshold", lambda v: isinstance(v, (int, float)) and 0.5 <= v <= 1.0,
     "boolean_threshold (theta) must be in [0.5, 1.0]"),
    ("boolean_delta", lambda v: isinstance(v, (int, float)) and 0.01 <= v <= 0.5,
     "boolean_delta must be in [0.01, 0.5]"),
    ("early_stop_confidence", lambda v: isinstance(v, (int, float)) and 0.5 <= v <= 1.0,
     "early_stop_confidence must be in [0.5, 1.0]"),
]


def validate_config(cfg: ScanConfig) -> None:
    """Raise ConfigError on the first violated rule."""
    # target scheme
    parsed = urlparse(cfg.target)
    if parsed.scheme not in ("http", "https"):
        raise ConfigError("target must be an http(s) URL")
    if not parsed.netloc:
        raise ConfigError("target must include a host")
    for field_name, ok, msg in _RULES:
        if not ok(getattr(cfg, field_name)):
            raise ConfigError(msg)
    # delta must leave a usable band below theta
    if cfg.boolean_delta >= cfg.boolean_threshold:
        raise ConfigError("boolean_delta must be smaller than boolean_threshold")


def load_config_from_dict(d: dict[str, Any]) -> ScanConfig:
    known = {f for f in ScanConfig.__dataclass_fields__}
    clean = {k: v for k, v in d.items() if k in known}
    if "target" not in clean:
        raise ConfigError("target is required")
    cfg = ScanConfig(**clean)
    validate_config(cfg)
    return cfg


def load_config_from_cli(args: Any) -> ScanConfig:
    """Build config from an argparse Namespace."""
    d = {
        "target": args.target,
        "consent": bool(getattr(args, "i_am_authorized", False)),
        "allowlist": list(getattr(args, "allow", []) or []),
        "max_depth": getattr(args, "max_depth", 2),
        "max_pages": getattr(args, "max_pages", 50),
        "rate_limit_rps": getattr(args, "rate", 5.0),
        "scan_deadline_s": getattr(args, "deadline", 120.0),
        "max_requests": getattr(args, "max_requests", 2000),
    }
    if getattr(args, "cookie", None):
        d["cookie"] = args.cookie
    return load_config_from_dict(d)


def config_public_summary(cfg: ScanConfig) -> dict[str, Any]:
    """Config safe to display/store (cookie masked)."""
    return cfg.public_summary()
