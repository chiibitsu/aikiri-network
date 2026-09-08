"""Canonical bytes and closed schemas.

Two rules hold everything else up:

  canonical = JSON, sorted keys, no whitespace, ASCII-escaped, no NaN or
  Infinity, and a domain prefix in front of every hash so bytes signed for
  one purpose can never be replayed as another.

The exact bytes are frozen in tests/vectors/. Changing them is a protocol
version change, not an edit.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata

from .errors import SchemaError

BLOCK_DOMAIN_V2 = b"aikiri-ledger/block/v2\n"
APPROVAL_DOMAIN_V1 = b"aikiri-ledger/approval/v1\n"
REQUEST_DOMAIN_V1 = b"aikiri-ledger/request/v1\n"
TRUST_DOMAIN_V1 = b"aikiri-ledger/trust/v1\n"

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX = re.compile(r"\A[0-9a-f]+\Z")


def canonical_bytes(obj) -> bytes:
    """ASCII-only, sorted, compact, no NaN. Platform and version independent."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def domain_hash(domain: bytes, obj) -> str:
    return hashlib.sha256(domain + canonical_bytes(obj)).hexdigest()


def _no_constants(token):
    raise SchemaError(f"canonical JSON admits no {token}")


def loads_strict(text: str | bytes):
    """Parse with NaN, Infinity and -Infinity refused rather than accepted."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as e:
            raise SchemaError(f"not valid UTF-8: {e}") from e
    try:
        return json.loads(text, parse_constant=_no_constants)
    except json.JSONDecodeError as e:
        raise SchemaError(f"not valid JSON: {e}") from e


def strict(obj, required: tuple[str, ...], name: str) -> dict:
    """Exactly these keys. Nothing missing, nothing extra, no surprises."""
    if not isinstance(obj, dict):
        raise SchemaError(f"{name}: expected an object, got {type(obj).__name__}")
    keys = set(obj)
    want = set(required)
    if keys - want:
        raise SchemaError(f"{name}: unknown field(s) {sorted(keys - want)}")
    if want - keys:
        raise SchemaError(f"{name}: missing field(s) {sorted(want - keys)}")
    return obj


def hex64(value, field: str) -> str:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise SchemaError(f"{field}: expected 64 lowercase hex characters")
    return value


def hexstr(value, field: str, *, even: bool = True) -> str:
    if not isinstance(value, str) or not value or not _HEX.match(value):
        raise SchemaError(f"{field}: expected lowercase hex")
    if even and len(value) % 2:
        raise SchemaError(f"{field}: odd-length hex")
    return value


def plain_str(value, field: str, *, max_len: int = 64) -> str:
    """A short, NFC-normalised, printable label. No control characters, no
    unnormalised lookalikes that would compare equal to a human and not to bytes."""
    if not isinstance(value, str):
        raise SchemaError(f"{field}: expected a string")
    if not value or len(value) > max_len:
        raise SchemaError(f"{field}: length must be 1..{max_len}")
    if value != unicodedata.normalize("NFC", value):
        raise SchemaError(f"{field}: must be NFC-normalised")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise SchemaError(f"{field}: control characters are not allowed")
    return value


def exact_int(value, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaError(f"{field}: expected an integer")
    return value
