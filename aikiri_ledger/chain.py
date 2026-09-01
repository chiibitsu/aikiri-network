"""Aikiri Ledger ~ the chain.

One block per day. Only roots, hashes and signatures ever enter a block.
Content never does. One validator for now; members become validators
later by signing each other's blocks.

Block (v1):
  index, timestamp, prev_hash, roots[], merkle_root, validator,
  signature, hash

Canonical bytes = JSON, sorted keys, no whitespace, UTF-8, excluding
`signature` and `hash`. hash = sha256(canonical). signature =
ed25519(sk, hash). Chain valid iff prev links hold and every signature
verifies against its validator key.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

GENESIS_TEXT = "Aikiri Network ~ genesis ~ love, light, logic, legacy"
MANILA = timezone(timedelta(hours=8))
ROOT_KINDS = {"journal", "scenario", "revocation", "deliverable", "acceptance", "raw"}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Merkle root over hex sha256 leaves. Empty -> sha256 of empty bytes.
    Odd levels duplicate the last node (Bitcoin-style)."""
    if not leaves:
        return sha256_hex(b"")
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


@dataclass
class Root:
    kind: str
    sha256: str
    ref: str = ""  # path, scenario id, or "of:<id>" for revocations. Never content.

    def __post_init__(self):
        if self.kind not in ROOT_KINDS:
            raise ValueError(f"unknown root kind: {self.kind}")
        if len(self.sha256) != 64:
            raise ValueError("root sha256 must be 64 hex chars")
        bytes.fromhex(self.sha256)


@dataclass
class Block:
    index: int
    timestamp: str
    prev_hash: str
    roots: list[dict] = field(default_factory=list)
    merkle_root: str = ""
    validator: str = ""
    signature: str = ""
    hash: str = ""

    # ---- canonical form ----
    def canonical(self) -> bytes:
        d = asdict(self)
        d.pop("signature", None)
        d.pop("hash", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def compute_hash(self) -> str:
        return sha256_hex(self.canonical())

    def sign(self, sk: SigningKey) -> "Block":
        self.validator = sk.verify_key.encode().hex()
        self.merkle_root = merkle_root([r["sha256"] for r in self.roots])
        self.hash = self.compute_hash()
        self.signature = sk.sign(bytes.fromhex(self.hash)).signature.hex()
        return self

    def verify_self(self) -> tuple[bool, str]:
        if self.merkle_root != merkle_root([r["sha256"] for r in self.roots]):
            return False, "merkle_root mismatch"
        if self.hash != self.compute_hash():
            return False, "hash mismatch"
        try:
            VerifyKey(bytes.fromhex(self.validator)).verify(bytes.fromhex(self.hash), bytes.fromhex(self.signature))
        except (BadSignatureError, ValueError):
            return False, "bad signature"
        return True, "ok"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "Block":
        d = json.loads(text)
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


class Ledger:
    """Append-only directory of blocks. Working copy lives in git; truth is
    the chain of hashes, witnessed by Base and Bitcoin."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.blocks_dir = self.root / "blocks"
        self.queue_path = self.root / "queue.json"
        self.head_path = self.root / "HEAD"

    # ---- filesystem ----
    def _block_path(self, index: int) -> Path:
        return self.blocks_dir / f"{index:06d}.json"

    def exists(self) -> bool:
        return self._block_path(0).exists()

    def head(self) -> Block:
        idx = int(self.head_path.read_text().split()[0])
        return self.read(idx)

    def read(self, index: int) -> Block:
        return Block.from_json(self._block_path(index).read_text())

    def blocks(self) -> Iterable[Block]:
        i = 0
        while self._block_path(i).exists():
            yield self.read(i)
            i += 1

    def _append(self, block: Block) -> Path:
        p = self._block_path(block.index)
        if p.exists():
            raise FileExistsError(f"block {block.index} already exists; ledger is append-only")
        self.blocks_dir.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(block.to_json())
        os.replace(tmp, p)  # atomic
        self.head_path.write_text(f"{block.index} {block.hash}\n")
        return p

    # ---- lifecycle ----
    def init(self, sk: SigningKey, now: datetime | None = None) -> Block:
        if self.exists():
            raise FileExistsError("ledger already initialised")
        now = now or datetime.now(MANILA)
        genesis = Block(index=0, timestamp=now.isoformat(), prev_hash=sha256_hex(GENESIS_TEXT.encode()), roots=[])
        genesis.sign(sk)
        self._append(genesis)
        return genesis

    def seal(self, root: Root) -> None:
        q = json.loads(self.queue_path.read_text()) if self.queue_path.exists() else []
        q.append(asdict(root))
        self.queue_path.write_text(json.dumps(q, indent=2) + "\n")

    def queue(self) -> list[dict]:
        return json.loads(self.queue_path.read_text()) if self.queue_path.exists() else []

    def block(self, sk: SigningKey, now: datetime | None = None, allow_empty: bool = False) -> Block:
        roots = self.queue()
        if not roots and not allow_empty:
            raise ValueError("nothing sealed since last block; refusing to write an empty block")
        prev = self.head()
        now = now or datetime.now(MANILA)
        b = Block(index=prev.index + 1, timestamp=now.isoformat(), prev_hash=prev.hash, roots=roots)
        b.sign(sk)
        self._append(b)
        if self.queue_path.exists():
            self.queue_path.unlink()
        return b

    def verify(self) -> tuple[bool, list[str]]:
        """Chain integrity + signatures. Witnesses are checked separately."""
        report: list[str] = []
        prev: Block | None = None
        for b in self.blocks():
            ok, why = b.verify_self()
            if not ok:
                report.append(f"block {b.index}: {why}")
                return False, report
            if prev is None:
                if b.index != 0 or b.prev_hash != sha256_hex(GENESIS_TEXT.encode()):
                    report.append("block 0: not a valid genesis")
                    return False, report
            else:
                if b.index != prev.index + 1:
                    report.append(f"block {b.index}: index gap after {prev.index}")
                    return False, report
                if b.prev_hash != prev.hash:
                    report.append(f"block {b.index}: prev_hash does not match block {prev.index}")
                    return False, report
            report.append(f"block {b.index}: ok ({len(b.roots)} roots)")
            prev = b
        if prev is None:
            report.append("no blocks")
            return False, report
        head_idx, head_hash = self.head_path.read_text().split()
        if int(head_idx) != prev.index or head_hash != prev.hash:
            report.append("HEAD does not match last block")
            return False, report
        return True, report


# ---- keys (kept outside the repo; never committed) ----
VALIDATOR_KEY_ENV = "AIKIRI_VALIDATOR_KEY"


def new_key() -> SigningKey:
    return SigningKey.generate()


def parse_key(material: str | bytes) -> SigningKey:
    """Accepts a 32-byte ed25519 seed as raw bytes, 64 hex chars (0x optional),
    or base64. Anything else is rejected rather than guessed."""
    import base64
    import binascii

    if isinstance(material, bytes) and len(material) == 32:
        return SigningKey(material)
    text = material.decode("utf-8", "strict") if isinstance(material, bytes) else material
    text = text.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if len(text) == 64:
        try:
            return SigningKey(bytes.fromhex(text))
        except ValueError:
            pass
    try:
        raw = base64.b64decode(text, validate=True)
        if len(raw) == 32:
            return SigningKey(raw)
    except (binascii.Error, ValueError):
        pass
    raise ValueError("validator key must be a 32-byte seed: raw, 64 hex chars, or base64")


def key_from_env(var: str = VALIDATOR_KEY_ENV) -> SigningKey | None:
    """The validator key from the environment (GitHub Actions secret), or None."""
    v = os.environ.get(var)
    return parse_key(v) if v else None


def save_key(sk: SigningKey, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(sk.encode())
    os.chmod(p, 0o600)


def load_key(path: str | Path) -> SigningKey:
    return parse_key(Path(path).read_bytes())
