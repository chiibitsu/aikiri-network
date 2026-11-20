"""A certificate cohort: many certificates sealed as one block, one proof each.

A block holds exactly one root. A cohort's root is the Merkle root of its
certificates' fingerprints, so one block seals the whole cohort, and each
certificate carries a short proof that its fingerprint is a leaf of that root.

Construction: the Merkle Tree Hash of RFC 9162 (Certificate Transparency v2),
section 2.1.1, with its audit path (2.1.3), but with text domain prefixes in
place of RFC 9162's single 0x00 / 0x01 bytes, in the style of every other hash
on this ledger:

    leaf(fp)   = SHA-256("aikiri-ledger/cert-leaf/v1\\n" || fp)        fp: 32 bytes
    node(l, r) = SHA-256("aikiri-ledger/cert-node/v1\\n" || l || r)
    MTH([d])   = leaf(d)
    MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n]))   k: largest power of 2 below n

The prefixes differ, so a leaf can never pose as a node or a node as a leaf.
An odd count is not padded: the split at k leaves the last subtree smaller,
and nothing is ever duplicated (the v1 merkle_root did, which let [a,b,c] and
[a,b,c,c] share a root). The leaves are the fingerprints sorted and distinct,
so one set of certificates has exactly one root, whatever order it came in.

The proof is JSON, closed schema:

    {"v": 1, "leaf": "<fingerprint>", "root": "<cohort root>", "block": <index> | null,
     "path": [{"side": "left" | "right", "sha256": "<sibling>"}, ...]}

`path` runs from the leaf up. `side` is where the sibling sits: "left" means
the next hash is node(sibling, current). A single-certificate cohort has an
empty path and its root is leaf(fp). `block` is the index of the block that
seals the root; null in a proof written before a block was asked for.

The fingerprints are opaque here. What they are fingerprints of, and why that
is safe to make public, is docs/certificates.md.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import date

from .canonical import canonical_bytes, exact_int, hex64, plain_str, strict
from .errors import SchemaError

JSON_MAX = 1 << 16   # no proof, record or pointer file comes near this


def _no_constant(token):
    raise SchemaError(f"canonical JSON admits no {token}")


def _no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise SchemaError(f"duplicate key {k!r}: one file, one reading")
        d[k] = v
    return d


def _loads(value):
    """Strict JSON as canonical.loads_strict reads it (no NaN, no Infinity), and also: bounded in size, no duplicate keys (another reader could take
    the other copy), and every way the parser can fail is a SchemaError, never a crash."""
    if not isinstance(value, (str, bytes)):
        return value
    if len(value) > JSON_MAX:
        raise SchemaError("too large to be a proof or a record")
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            raise SchemaError("not valid UTF-8")
    try:
        return json.loads(value, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (ValueError, RecursionError) as e:     # a SchemaError is a ValueError
        raise e if isinstance(e, SchemaError) else SchemaError(f"not valid JSON: {e}")

KIND = "cert-cohort"
LEAF_DOMAIN = b"aikiri-ledger/cert-leaf/v1\n"
NODE_DOMAIN = b"aikiri-ledger/cert-node/v1\n"
PROOF_VERSION = 1
PROOF_FIELDS = ("v", "leaf", "root", "block", "path")
STEP_FIELDS = ("side", "sha256")
SIDES = ("left", "right")
MAX_LEAVES = 1 << 16   # a course cohort, with room to spare; keeps every path at 16 steps or fewer
MAX_PATH = 16

# The issuer record: the format only. A real record never enters this repository.
RECORD_DOMAIN = b"aikiri-ledger/cert-record/v1\n"
RECORD_VERSION = 1
RECORD_FIELDS = ("v", "number", "holder", "course", "completed", "issuer", "instructor")
RECORD_OPTIONAL = ("host",)
RECORD_TEXT_MAX = 200
ISSUER = "Chiibitsu Labs"   # format v1: the only issuer a v1 record can name
_NUMBER = re.compile(r"\A(?:[0-9a-f]{2}){16,32}\Z")   # 128 to 256 bits, lowercase hex
_DATE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")
_B64URL = re.compile(r"\A[A-Za-z0-9_-]+\Z")
PAYLOAD_MAX = 4096

# The public layout under ledger/: hashes only, never a record field.
CERTS_DIR = "certs"
REVOKED_DIR = "revoked"
REVOKED_FIELDS = ("v", "fingerprint", "block")


def leaf_hash(fp: str) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + bytes.fromhex(hex64(fp, "leaf"))).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two strictly below n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def leaves(fingerprints) -> list[str]:
    """Sorted, distinct, 64 lowercase hex each, at least one, at most MAX_LEAVES."""
    fps = [hex64(f, "fingerprint") for f in fingerprints]
    if not fps:
        raise SchemaError("a cohort needs at least one certificate")
    if len(fps) > MAX_LEAVES:
        raise SchemaError(f"a cohort holds at most {MAX_LEAVES} certificates (got {len(fps)})")
    if len(set(fps)) != len(fps):
        raise SchemaError("the same fingerprint appears twice; each certificate has its own")
    return sorted(fps)


def _mth(level: list[bytes]) -> bytes:
    if len(level) == 1:
        return level[0]
    k = _split(len(level))
    return node_hash(_mth(level[:k]), _mth(level[k:]))


def _path(level: list[bytes], m: int) -> list[dict]:
    """RFC 9162 PATH(m, D), leaf first, each sibling with the side it sits on."""
    if len(level) == 1:
        return []
    k = _split(len(level))
    if m < k:
        return _path(level[:k], m) + [{"side": "right", "sha256": _mth(level[k:]).hex()}]
    return _path(level[k:], m - k) + [{"side": "left", "sha256": _mth(level[:k]).hex()}]


def root(fingerprints) -> str:
    return _mth([leaf_hash(f) for f in leaves(fingerprints)]).hex()


def build(fingerprints, block: int | None = None) -> tuple[str, list[dict]]:
    """The cohort's root and one proof per certificate, in leaf order."""
    fps = leaves(fingerprints)
    level = [leaf_hash(f) for f in fps]
    r = _mth(level).hex()
    return r, [{"v": PROOF_VERSION, "leaf": fp, "root": r, "block": block, "path": _path(level, i)}
               for i, fp in enumerate(fps)]


def parse_proof(value) -> dict:
    """Closed schema: exactly these fields, nothing extra, nothing loose."""
    d = _loads(value)
    strict(d, PROOF_FIELDS, "proof")
    if exact_int(d["v"], "proof.v") != PROOF_VERSION:
        raise SchemaError(f"proof.v: expected {PROOF_VERSION}, got {d['v']}")
    block = d["block"]
    if block is not None and exact_int(block, "proof.block") < 1:
        raise SchemaError("proof.block: a block index, at least 1, or null")
    path = d["path"]
    if not isinstance(path, list) or len(path) > MAX_PATH:
        raise SchemaError(f"proof.path: a list of at most {MAX_PATH} steps")
    steps = []
    for i, s in enumerate(path):
        strict(s, STEP_FIELDS, f"proof.path[{i}]")
        if s["side"] not in SIDES:
            raise SchemaError(f"proof.path[{i}].side: 'left' or 'right'")
        steps.append({"side": s["side"], "sha256": hex64(s["sha256"], f"proof.path[{i}].sha256")})
    return {"v": PROOF_VERSION, "leaf": hex64(d["leaf"], "proof.leaf"),
            "root": hex64(d["root"], "proof.root"), "block": block, "path": steps}


def root_from_path(leaf: str, path: list[dict]) -> str:
    h = leaf_hash(leaf)
    for s in path:
        sib = bytes.fromhex(s["sha256"])
        h = node_hash(sib, h) if s["side"] == "left" else node_hash(h, sib)
    return h.hex()


def verify_proof(proof) -> bool:
    """Pure: does the path take this leaf to this root? No ledger, no network, no I/O.
    A malformed proof is False, never an exception."""
    try:
        p = parse_proof(proof)
    except (SchemaError, TypeError, ValueError, RecursionError):
        return False
    return root_from_path(p["leaf"], p["path"]) == p["root"]


def proof_json(proof: dict) -> str:
    """Canonical bytes: one proof, one file content, wherever it is written."""
    return canonical_bytes(parse_proof(proof)).decode() + "\n"


# --- the issuer record, its fingerprint and its link payload ---------------------------

def _text(value, field: str) -> str:
    v = plain_str(value, field, max_len=RECORD_TEXT_MAX)
    if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
        raise SchemaError(f"{field}: lone surrogates are not text")
    return v


def parse_record(value) -> dict:
    """Closed schema: the seven fields, plus `host` only if the certificate names one."""
    d = _loads(value)
    if not isinstance(d, dict):
        raise SchemaError("record: expected an object")
    strict(d, RECORD_FIELDS + tuple(k for k in RECORD_OPTIONAL if k in d), "record")
    if exact_int(d["v"], "record.v") != RECORD_VERSION:
        raise SchemaError(f"record.v: expected {RECORD_VERSION}, got {d['v']}")
    if not isinstance(d["number"], str) or not _NUMBER.match(d["number"]):
        raise SchemaError("record.number: 32 to 64 lowercase hex (128 to 256 random bits)")
    c = d["completed"]
    try:
        if not isinstance(c, str) or not _DATE.match(c):
            raise ValueError
        date.fromisoformat(c)
    except ValueError:
        raise SchemaError("record.completed: a date, YYYY-MM-DD")
    out = {"v": RECORD_VERSION, "number": d["number"], "completed": c}
    for k in ("holder", "course", "issuer", "instructor") + tuple(k for k in RECORD_OPTIONAL if k in d):
        out[k] = _text(d[k], f"record.{k}")
    if out["issuer"] != ISSUER:
        raise SchemaError(f"record.issuer: a v1 record is issued by {ISSUER!r} exactly")
    return out


def record_bytes(record) -> bytes:
    """Sorted keys, no whitespace, UTF-8 (not ASCII-escaped: this is the one encoding a
    browser's JSON.stringify of the same sorted object also gives, since parse_record has
    already refused control characters, lone surrogates and anything not NFC)."""
    return json.dumps(parse_record(record), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def record_fingerprint(record) -> str:
    """The certificate's fingerprint: the leaf of its cohort, the name of its public files."""
    return hashlib.sha256(RECORD_DOMAIN + record_bytes(record)).hexdigest()


def encode_payload(record) -> str:
    """base64url of the canonical bytes, no padding: what follows # in the link."""
    return base64.urlsafe_b64encode(record_bytes(record)).rstrip(b"=").decode("ascii")


def decode_payload(payload: str) -> dict:
    """Only the canonical encoding of a valid record is accepted: one record, one payload."""
    p = payload.strip()
    if "#" in p:
        p = p.split("#", 1)[1]
    if not p or len(p) > PAYLOAD_MAX or not _B64URL.match(p) or len(p) % 4 == 1:
        raise SchemaError("payload: not a certificate link")
    try:
        raw = base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))
    except (binascii.Error, ValueError):
        raise SchemaError("payload: not base64url")
    record = parse_record(raw)
    if encode_payload(record) != p:
        raise SchemaError("payload: not in canonical form")
    return record


def parse_revoked(value) -> dict:
    d = _loads(value)
    strict(d, REVOKED_FIELDS, "revoked")
    if exact_int(d["v"], "revoked.v") != 1:
        raise SchemaError("revoked.v: expected 1")
    if exact_int(d["block"], "revoked.block") < 1:
        raise SchemaError("revoked.block: a block index, at least 1")
    return {"v": 1, "fingerprint": hex64(d["fingerprint"], "revoked.fingerprint"), "block": d["block"]}


def revoked_json(fingerprint: str, block: int) -> str:
    return canonical_bytes(parse_revoked({"v": 1, "fingerprint": fingerprint, "block": block})).decode() + "\n"


def read_fingerprints(text: str) -> list[str]:
    """The input contract: one 64-hex fingerprint per line. Blank lines are skipped;
    capitals and a 0x prefix are lowered and dropped; anything else is refused by line."""
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        v = line.strip(" \t\r").lower()
        if not v:
            continue
        if v.startswith("0x"):
            v = v[2:]
        try:
            out.append(hex64(v, "fingerprint"))
        except SchemaError:
            raise SchemaError(f"line {n}: expected one 64-hex fingerprint")
    return out


def status(proof: dict, ledger) -> tuple[str, list[str]]:
    """What a proof says against a ledger: VALID, REVOKED, NOT FOUND or INVALID, with the
    reasons. It reads the ledger the way the check page does: the block the proof names,
    by its index, must hold this root as its one cert-cohort root, and any revocation block
    naming the fingerprint revokes it. The chain's own state is verify's to report."""
    if not verify_proof(proof):
        return "INVALID", ["the path does not lead from this certificate to the root it names"]
    p = parse_proof(proof)
    if p["block"] is None:
        return "NOT FOUND", ["the proof names no block yet: it is from `cohort build`, or not sealed"]
    blocks = {b.index: b for b in ledger.blocks()}
    blk = blocks.get(p["block"])
    if blk is None:
        return "NOT FOUND", [f"block {p['block']} is not on this ledger (not sealed yet, never "
                             f"approved, or this copy is behind: git pull)"]
    if blk.roots != [{"kind": KIND, "sha256": p["root"]}]:
        return "NOT FOUND", [f"block {p['block']} does not seal cohort {p['root']}"]
    lines = [f"in cohort {p['root']}, sealed in block {blk.index} ({blk.timestamp})"]
    revoked = [b for b in blocks.values()
               if b.roots == [{"kind": "revocation", "sha256": p["leaf"]}]]
    if revoked:
        b = min(revoked, key=lambda b: b.index)
        return "REVOKED", lines + [f"revoked in block {b.index} ({b.timestamp})"]
    return "VALID", lines
