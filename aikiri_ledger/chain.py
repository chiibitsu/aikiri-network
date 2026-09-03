"""Aikiri Ledger ~ the chain.

One block per sealed request. Only roots, hashes and signatures ever enter a
block. Content never does, and neither does a path: `ref` was removed in v2
because a vault path is structure about a private life.

Block (v2):
  v, index, timestamp, prev_hash, roots[1], nonce, approval, validator,
  signature, hash

  canonical  = JSON, sorted keys, compact, ASCII-escaped, excluding
               `signature` and `hash`
  hash       = sha256(b"aikiri-ledger/block/v2\\n" + canonical)
  signature  = ed25519(validator key, hash)
  approval   = P-256 signature from a registered Secure Enclave device over
               index, prev_hash, roots, nonce and validator

The approval sits inside the hashed bytes, so it cannot be stripped or swapped
without breaking both the hash and the validator signature.

Blocks 0 and 1 predate this format. They are v1, they are anchored on Base,
and their bytes are frozen. They verify only when their hash matches the one
pinned in an external trust anchor; a v1-shaped block anywhere else is refused.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from .canonical import (BLOCK_DOMAIN_V2, canonical_bytes, domain_hash, exact_int, hex64,
                        hexstr, loads_strict, strict)
from .errors import SchemaError
from .request import Request, parse_roots

GENESIS_TEXT = "Aikiri Network ~ genesis ~ love, light, logic, legacy"
MANILA = timezone(timedelta(hours=8))
BLOCK_VERSION = 2

V1_FIELDS = ("index", "timestamp", "prev_hash", "roots", "merkle_root",
             "validator", "signature", "hash")
V2_FIELDS = ("v", "index", "timestamp", "prev_hash", "roots", "nonce",
             "approval", "validator", "signature", "hash")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """v1 only. Kept so blocks 0 and 1 still verify; v2 dropped it because the
    roots are already inside the hashed bytes and the odd-leaf duplication made
    [a,b,c] and [a,b,c,c] share a root."""
    if not leaves:
        return sha256_hex(b"")
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def parse_timestamp(value, field: str = "timestamp") -> datetime:
    if not isinstance(value, str):
        raise SchemaError(f"{field}: expected an RFC 3339 string")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as e:
        raise SchemaError(f"{field}: not RFC 3339: {e}") from e
    if dt.tzinfo is None:
        raise SchemaError(f"{field}: must carry a UTC offset")
    return dt


class Block:
    """A block as it sits on disk. Version 1 and 2 are both readable; only
    version 2 can be written."""

    def __init__(self, raw: dict, version: int):
        self.raw = raw
        self.version = version

    # ---- reading ----
    @classmethod
    def parse(cls, text) -> "Block":
        d = loads_strict(text)
        if not isinstance(d, dict):
            raise SchemaError("block: expected an object")
        if "v" not in d:
            return cls._parse_v1(d)
        if exact_int(d["v"], "block.v") != BLOCK_VERSION:
            raise SchemaError(f"block.v: unsupported version {d['v']!r}")
        return cls._parse_v2(d)

    @classmethod
    def _parse_v1(cls, d: dict) -> "Block":
        strict(d, V1_FIELDS, "block (v1)")
        exact_int(d["index"], "block.index")
        parse_timestamp(d["timestamp"])
        for f in ("prev_hash", "merkle_root", "validator", "hash"):
            hex64(d[f], f"block.{f}")
        hexstr(d["signature"], "block.signature")
        if not isinstance(d["roots"], list):
            raise SchemaError("block.roots: expected a list")
        for i, r in enumerate(d["roots"]):
            strict(r, ("kind", "sha256", "ref"), f"block.roots[{i}] (v1)")
            hex64(r["sha256"], f"block.roots[{i}].sha256")
        return cls(d, 1)

    @classmethod
    def _parse_v2(cls, d: dict) -> "Block":
        from .approval import APPROVAL_FIELDS
        strict(d, V2_FIELDS, "block")
        exact_int(d["index"], "block.index")
        parse_timestamp(d["timestamp"])
        for f in ("prev_hash", "nonce", "validator", "hash"):
            hex64(d[f], f"block.{f}")
        hexstr(d["signature"], "block.signature")
        parse_roots(d["roots"], "block.roots")
        strict(d["approval"], APPROVAL_FIELDS, "block.approval")
        return cls(d, BLOCK_VERSION)

    # ---- fields ----
    @property
    def index(self) -> int:
        return self.raw["index"]

    @property
    def timestamp(self) -> str:
        return self.raw["timestamp"]

    @property
    def when(self) -> datetime:
        return parse_timestamp(self.raw["timestamp"])

    @property
    def prev_hash(self) -> str:
        return self.raw["prev_hash"]

    @property
    def roots(self) -> list:
        return self.raw["roots"]

    @property
    def hash(self) -> str:
        return self.raw["hash"]

    @property
    def validator(self) -> str:
        return self.raw["validator"]

    @property
    def signature(self) -> str:
        return self.raw["signature"]

    @property
    def nonce(self) -> str | None:
        return self.raw.get("nonce")

    @property
    def approval(self) -> dict | None:
        return self.raw.get("approval")

    # ---- hashing ----
    def _body(self) -> dict:
        return {k: v for k, v in self.raw.items() if k not in ("signature", "hash")}

    def canonical(self) -> bytes:
        if self.version == 1:  # frozen: the bytes blocks 0 and 1 were hashed as
            return json.dumps(self._body(), sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        return BLOCK_DOMAIN_V2 + canonical_bytes(self._body())

    def compute_hash(self) -> str:
        return sha256_hex(self.canonical())

    def verify_self(self) -> tuple[bool, str]:
        if self.version == 1:
            expected = merkle_root([r["sha256"] for r in self.roots])
            if self.raw["merkle_root"] != expected:
                return False, "merkle_root mismatch"
        if self.hash != self.compute_hash():
            return False, "hash does not match its own contents"
        try:
            VerifyKey(bytes.fromhex(self.validator)).verify(
                bytes.fromhex(self.hash), bytes.fromhex(self.signature))
        except (BadSignatureError, ValueError):
            return False, "validator signature does not verify"
        return True, "ok"

    def to_json(self) -> str:
        ascii_only = self.version != 1
        return json.dumps(self.raw, indent=2, sort_keys=True,
                          ensure_ascii=ascii_only) + "\n"


class Ledger:
    """Append-only directory. Blocks in blocks/, witness proofs in proofs/,
    incoming sealed requests in requests/. Nothing is ever rewritten."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.blocks_dir = self.root / "blocks"
        self.proofs_dir = self.root / "proofs"
        self.requests_dir = self.root / "requests"
        self.head_path = self.root / "HEAD"

    # ---- paths ----
    def _block_path(self, index: int) -> Path:
        return self.blocks_dir / f"{index:06d}.json"

    def proof_path(self, index: int, suffix: str) -> Path:
        return self.proofs_dir / f"{index:06d}.{suffix}"

    def pending_path(self, index: int) -> Path:
        return self.proofs_dir / f"{index:06d}.base.pending.json"

    # ---- reading ----
    def exists(self) -> bool:
        return self._block_path(0).exists()

    def read(self, index: int) -> Block:
        return Block.parse(self._block_path(index).read_text())

    def head(self) -> Block:
        return self.read(int(self.head_path.read_text().split()[0]))

    def blocks(self) -> Iterable[Block]:
        i = 0
        while self._block_path(i).exists():
            yield self.read(i)
            i += 1

    def height(self) -> int:
        i = 0
        while self._block_path(i).exists():
            i += 1
        return i - 1

    # ---- writing ----
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

    def init(self, sk: SigningKey, now: datetime | None = None) -> Block:
        """Genesis is v1 by construction: it reproduces the block already anchored
        on Base. Its hash must be pinned in the trust anchor to be accepted."""
        if self.exists():
            raise FileExistsError("ledger already initialised")
        now = now or datetime.now(MANILA)
        raw = {"index": 0, "timestamp": now.isoformat(),
               "prev_hash": sha256_hex(GENESIS_TEXT.encode()), "roots": [],
               "merkle_root": merkle_root([]), "validator": sk.verify_key.encode().hex(),
               "signature": "", "hash": ""}
        b = Block(raw, 1)
        raw["hash"] = b.compute_hash()
        raw["signature"] = sk.sign(bytes.fromhex(raw["hash"])).signature.hex()
        self.root.mkdir(parents=True, exist_ok=True)
        self._append(b)
        return b

    def nonces(self) -> set[str]:
        return {b.nonce for b in self.blocks() if b.nonce}

    def consume(self, request: Request) -> Block:
        """Check a sealed request against the head. Raises rather than guessing."""
        head = self.head()
        if request.index != head.index + 1:
            raise ValueError(f"request is for index {request.index}, the chain is at "
                             f"{head.index}; the next block is {head.index + 1}")
        if request.prev_hash != head.hash:
            raise ValueError(f"request prev_hash does not match block {head.index}")
        if request.nonce in self.nonces():
            raise ValueError(f"request nonce already used in this chain; a request is "
                             f"consumed exactly once")
        return head

    def append_from_request(self, request: Request, sk: SigningKey, now: datetime | None = None,
                            registered=None) -> Block:
        head = self.consume(request)
        validator = sk.verify_key.encode().hex()
        if request.validator != validator:
            raise ValueError("request was approved for a different validator key")
        ok, why = request.verify(registered)
        if not ok:
            raise ValueError(f"refusing to write an unapproved block: {why}")
        now = now or datetime.now(MANILA)
        if now <= head.when:
            raise ValueError(f"timestamp {now.isoformat()} is not after block "
                             f"{head.index} ({head.timestamp})")
        raw = {"v": BLOCK_VERSION, "index": request.index, "timestamp": now.isoformat(),
               "prev_hash": request.prev_hash, "roots": request.roots, "nonce": request.nonce,
               "approval": request.approval, "validator": validator,
               "signature": "", "hash": ""}
        raw["hash"] = domain_hash(BLOCK_DOMAIN_V2,
                                  {k: v for k, v in raw.items() if k not in ("signature", "hash")})
        raw["signature"] = sk.sign(bytes.fromhex(raw["hash"])).signature.hex()
        b = Block(raw, BLOCK_VERSION)
        self._append(b)
        return b

    # ---- witnessing: broadcast is not the same event as confirmation ----
    def write_pending(self, index: int, tx: str | None, account: str,
                      tx_nonce: int | None = None) -> Path:
        """Written before a transaction goes out. If the receipt lookup times out,
        this marker is what stops the next run from sending a second one."""
        self.proofs_dir.mkdir(parents=True, exist_ok=True)
        p = self.pending_path(index)
        p.write_text(json.dumps({"index": index, "tx": tx, "account": account,
                                 "txNonce": tx_nonce,
                                 "sentAt": datetime.now(timezone.utc).isoformat()},
                                indent=2, sort_keys=True) + "\n")
        return p

    def anchor_with_marker(self, base, block: Block, on_broadcast=None) -> str:
        from .witness import write_base_receipt
        if self.pending_path(block.index).exists():
            raise RuntimeError(
                f"block {block.index} has a pending anchor marker. A transaction may already "
                f"be in flight. Run `aikiri-ledger reconcile` before anchoring again.")
        if self.proof_path(block.index, "base.json").exists():
            raise RuntimeError(f"block {block.index} is already anchored")
        tx_nonce = None
        try:
            tx_nonce = base.w3.eth.get_transaction_count(base.account)
        except Exception:  # an adapter without a live node; the marker still matters
            pass
        self.write_pending(block.index, None, getattr(base, "account", None), tx_nonce)
        if on_broadcast is not None:
            on_broadcast(self.pending_path(block.index))
        tx = base.anchor(block)
        self.write_pending(block.index, tx, getattr(base, "account", None), tx_nonce)
        write_base_receipt(self, block, tx, base.contract.address,
                           base.w3.eth.chain_id, rcpt=base.last_receipt)
        self.pending_path(block.index).unlink(missing_ok=True)
        return tx

    def reconcile(self, base) -> list[int]:
        """Finish anchors whose receipt we never saw. Reads the chain; sends nothing."""
        from .witness import write_base_receipt
        done = []
        if not self.proofs_dir.exists():
            return done
        for p in sorted(self.proofs_dir.glob("*.base.pending.json")):
            d = loads_strict(p.read_text())
            index = int(d["index"])
            block = self.read(index)
            if not base.matches(block):
                continue  # still not on chain: leave the marker, do not re-send
            rcpt = None
            if d.get("tx"):
                tx = d["tx"] if str(d["tx"]).startswith("0x") else "0x" + str(d["tx"])
                try:
                    rcpt = base.w3.eth.get_transaction_receipt(tx)
                except Exception:
                    rcpt = None
            write_base_receipt(self, block, d.get("tx") or "", base.contract.address,
                               base.w3.eth.chain_id, rcpt=rcpt)
            p.unlink()
            done.append(index)
        return done


# ---- validator key (kept outside the repo; never committed) ----
VALIDATOR_KEY_ENV = "AIKIRI_VALIDATOR_KEY"


def new_key() -> SigningKey:
    return SigningKey.generate()


def parse_key(material: str | bytes) -> SigningKey:
    """A 32-byte ed25519 seed as raw bytes, 64 hex chars (0x optional), or base64."""
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
    v = os.environ.get(var)
    return parse_key(v) if v else None


def save_key(sk: SigningKey, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(sk.encode())
    os.chmod(p, 0o600)


def load_key(path: str | Path) -> SigningKey:
    return parse_key(Path(path).read_bytes())
