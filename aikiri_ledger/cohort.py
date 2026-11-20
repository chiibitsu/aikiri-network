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

import hashlib
import json

from .canonical import canonical_bytes, exact_int, hex64, loads_strict, strict
from .errors import SchemaError

KIND = "cert-cohort"
LEAF_DOMAIN = b"aikiri-ledger/cert-leaf/v1\n"
NODE_DOMAIN = b"aikiri-ledger/cert-node/v1\n"
PROOF_VERSION = 1
PROOF_FIELDS = ("v", "leaf", "root", "block", "path")
STEP_FIELDS = ("side", "sha256")
SIDES = ("left", "right")
MAX_LEAVES = 1 << 16   # a course cohort, with room to spare; keeps every path at 16 steps or fewer
MAX_PATH = 16


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
    d = loads_strict(value) if isinstance(value, (str, bytes)) else value
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
    except (SchemaError, TypeError, ValueError):
        return False
    return root_from_path(p["leaf"], p["path"]) == p["root"]


def proof_json(proof: dict) -> str:
    """Canonical bytes: one proof, one file content, wherever it is written."""
    return canonical_bytes(parse_proof(proof)).decode() + "\n"


def read_fingerprints(text: str) -> list[str]:
    """The input contract: one 64-hex fingerprint per line. Blank lines are skipped;
    capitals and a 0x prefix are lowered and dropped; anything else is refused by line."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        v = line.strip().lower()
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
    """What a proof says against a ledger: VALID, REVOKED, NOT SEALED or INVALID, with the
    reasons. Only the math and the blocks on this ledger copy; the chain's own state is
    verify's to report."""
    if not verify_proof(proof):
        return "INVALID", ["the path does not lead from this certificate to the root it names"]
    p = parse_proof(proof)
    sealed = None
    revoked = []
    for blk in ledger.blocks():
        for r in blk.roots:
            if r.get("sha256") == p["root"] and r.get("kind") == KIND and sealed is None:
                sealed = blk
            if r.get("sha256") == p["leaf"] and r.get("kind") == "revocation":
                revoked.append(blk)
    if sealed is None:
        return "NOT SEALED", [f"no {KIND} block on this ledger seals root {p['root']} "
                              f"(not sealed yet, or this copy is behind: git pull)"]
    if p["block"] is not None and p["block"] != sealed.index:
        return "INVALID", [f"the proof names block {p['block']}, but root {p['root']} is sealed "
                           f"in block {sealed.index}"]
    lines = [f"in cohort {p['root']}, sealed in block {sealed.index} ({sealed.timestamp})"]
    if revoked:
        b = revoked[0]
        return "REVOKED", lines + [f"revoked in block {b.index} ({b.timestamp})"]
    return "VALID", lines
