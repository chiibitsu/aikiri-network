"""Failures that must never be swallowed."""


class SchemaError(ValueError):
    """A document did not match its closed schema. Reject, never coerce."""


class TrustError(ValueError):
    """A trust anchor could not be established."""


class QuorumError(RuntimeError):
    """Independent sources disagreed, or too few answered. Never a success."""
