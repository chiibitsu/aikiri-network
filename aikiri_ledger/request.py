"""The sealed request: what the vault hands the ledger.

There is no queue. A queue is a mutable pile that anything with write access
can add to, and whatever is in it gets signed. A request is one approved
statement instead: exactly one root, bound to the index and prev_hash it is
meant for, carrying a nonce, approved on one of Chii's devices, and consumed
exactly once.

It is produced where the content lives (the vault) and travels to the ledger
as hashes only. Nothing here ever carries content, a path, or a filename.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from .canonical import (canonical_bytes, exact_int, hex64, loads_strict, plain_str, strict)
from .errors import SchemaError

REQUEST_FIELDS = ("v", "index", "prev_hash", "roots", "nonce", "validator", "approval")
ROOT_FIELDS = ("kind", "sha256")
ROOT_KINDS = ("journal", "scenario", "revocation", "deliverable", "acceptance", "raw")
REQUEST_VERSION = 1


def new_nonce() -> str:
    return secrets.token_hex(32)


def parse_roots(value, name: str = "roots") -> list[dict]:
    """Exactly one root in v2, closed schema, known kind. No ref, ever: a vault
    path is structure about a private life, and privacy is the default."""
    if not isinstance(value, list):
        raise SchemaError(f"{name}: expected a list")
    if len(value) != 1:
        raise SchemaError(f"{name}: exactly one root per block (got {len(value)})")
    out = []
    for i, r in enumerate(value):
        strict(r, ROOT_FIELDS, f"{name}[{i}]")
        kind = plain_str(r["kind"], f"{name}[{i}].kind", max_len=32)
        if kind not in ROOT_KINDS:
            raise SchemaError(f"{name}[{i}].kind: unknown kind {kind!r}")
        out.append({"kind": kind, "sha256": hex64(r["sha256"], f"{name}[{i}].sha256")})
    return out


@dataclass
class Request:
    v: int
    index: int
    prev_hash: str
    roots: list
    nonce: str
    validator: str
    approval: dict

    @classmethod
    def build(cls, *, index: int, prev_hash: str, roots: list, validator: str, approver,
              nonce: str | None = None) -> "Request":
        roots = parse_roots(roots)
        nonce = nonce or new_nonce()
        approval = approver.approve(index=index, prev_hash=prev_hash, roots=roots,
                                    nonce=nonce, validator=validator)
        return cls(REQUEST_VERSION, index, prev_hash, roots, nonce, validator, approval)

    @classmethod
    def unsigned(cls, *, index: int, prev_hash: str, roots: list, validator: str,
                 nonce: str | None = None) -> dict:
        """The payload a device is asked to approve. Shown to Chii before she touches
        the sensor, so she approves something she can read."""
        return {"v": REQUEST_VERSION, "index": index, "prev_hash": prev_hash,
                "roots": parse_roots(roots), "nonce": nonce or new_nonce(),
                "validator": validator}

    @classmethod
    def parse(cls, text) -> "Request":
        d = loads_strict(text)
        strict(d, REQUEST_FIELDS, "request")
        if exact_int(d["v"], "request.v") != REQUEST_VERSION:
            raise SchemaError(f"request.v: expected {REQUEST_VERSION}, got {d['v']}")
        index = exact_int(d["index"], "request.index")
        if index < 1:
            raise SchemaError("request.index: must be at least 1")
        from .approval import APPROVAL_FIELDS
        strict(d["approval"], APPROVAL_FIELDS, "request.approval")
        return cls(REQUEST_VERSION, index, hex64(d["prev_hash"], "request.prev_hash"),
                   parse_roots(d["roots"]), hex64(d["nonce"], "request.nonce"),
                   hex64(d["validator"], "request.validator"), dict(d["approval"]))

    def as_dict(self) -> dict:
        return {"v": self.v, "index": self.index, "prev_hash": self.prev_hash,
                "roots": self.roots, "nonce": self.nonce, "validator": self.validator,
                "approval": self.approval}

    def to_json(self) -> str:
        return canonical_bytes(self.as_dict()).decode() + "\n"

    def verify(self, registered) -> tuple[bool, str]:
        from .approval import verify_approval
        return verify_approval(self.approval, index=self.index, prev_hash=self.prev_hash,
                               roots=self.roots, nonce=self.nonce, validator=self.validator,
                               registered=registered)
