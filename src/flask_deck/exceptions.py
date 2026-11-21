from __future__ import annotations


class DeckError(Exception):
    """Base exception for all flask-deck errors."""


class SecurityConfigurationError(DeckError):
    """Raised when flask-deck is started in an insecure production configuration."""


class PermissionDeniedError(DeckError):
    """Raised when a user lacks permission to perform an operation."""


class ReadOnlyError(DeckError):
    """Raised when a mutating operation is attempted while read_only mode is enabled."""


class InvalidPKError(DeckError):
    """Raised when a primary key parameter cannot be decoded or coerced."""


class ValidationError(DeckError):
    """Raised when form or record validation fails."""

    def __init__(self, errors: dict[str, list[str]]) -> None:
        self.errors = errors
        summary = "; ".join(f"{field}: {', '.join(msgs)}" for field, msgs in errors.items())
        super().__init__(summary or "Validation failed")


class ImportLimitError(DeckError):
    """Raised when an import payload exceeds configured byte, row, or structure limits."""
