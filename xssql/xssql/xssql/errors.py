"""Exception hierarchy (DESIGN_DOC_V2 §8.1, v1.1).

All scanner-raised errors derive from ScannerError so callers (CLI, webapp)
can map them to exit codes / HTTP statuses in one place.
"""
from __future__ import annotations


class ScannerError(Exception):
    """Base class for all scanner errors."""


# --- configuration ---------------------------------------------------------
class ConfigError(ScannerError):
    """Invalid scan configuration."""


# --- ethics / scope (fail closed) ------------------------------------------
class EthicsError(ScannerError):
    """Base for authorization / scope failures."""


class ConsentRequiredError(EthicsError):
    """Scan attempted without explicit authorization."""


class ScopeViolation(EthicsError):
    """Target host is outside the permitted scope."""


# --- runtime budget --------------------------------------------------------
class BudgetError(ScannerError):
    """Base for budget-exhaustion conditions."""


class BudgetExceeded(BudgetError):
    """Request cap or deadline reached; scan must stop (partial results kept)."""


# --- network ---------------------------------------------------------------
class HttpError(ScannerError):
    """Unrecoverable transport error after retries."""


# --- storage ---------------------------------------------------------------
class StorageError(ScannerError):
    """Persistence-layer failure."""
