"""Sealing a client's document: one line from the app's chat, the hash only.

An app that issues documents (today the Kreativ Dental Blueprint flow) posts one
line per document for Chii to paste on the sealing machine:

    aikiri-ledger seal agreement <record id> <sha256>
    aikiri-ledger seal invoice   <record id> <sha256>
    aikiri-ledger seal-acceptance <record id> <sha256>   # older line, = seal agreement

The same line does both halves, so running it twice is how the seal finishes:

  1. Not in a block yet: writes the unsigned request for it (approve, commit,
     push; block.yml writes and anchors the block). An identical request already
     waiting is left as it is.
  2. In a block: writes nothing. With --report it tells the app which block and
     Base transaction sealed the file. The app ignores a repeat.

The record id never reaches the ledger. It is the key to the client's pages in
the app, so it travels only in the report, to the app that issued it. On the
ledger a document is a kind and a fingerprint, exactly like every other root.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .canonical import hex64, loads_strict
from .errors import SchemaError
from .request import parse_roots

# document -> root kind. Add a document here, and its kind to ROOT_KINDS.
DOCUMENTS = {"agreement": "acceptance", "invoice": "invoice"}
KIND_DOCUMENT = {kind: doc for doc, kind in DOCUMENTS.items()}
RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
NETWORK_CHECK = "https://www.chiibitsu.com/network/check"
SEAL_PATH = "/api/seal"
OTS_MAX = 50_000  # the app keeps at most this many characters of the proof
URL_ENV = "AIKIRI_SEAL_URL"
SECRET_ENV = "AIKIRI_SEAL_SECRET"


def kind_for(document: str) -> str:
    if document not in DOCUMENTS:
        raise SchemaError(f"document: expected one of {', '.join(DOCUMENTS)}, got {document!r}")
    return DOCUMENTS[document]


def record_id(value: str) -> str:
    if not isinstance(value, str) or not RECORD_ID.match(value):
        raise SchemaError("record id: 1 to 64 letters, digits, '-' or '_'")
    return value


def fingerprint(value: str) -> str:
    """Lowercase 64 hex. A pasted 0x prefix or capitals are forgiven; nothing else is."""
    v = value.strip().lower() if isinstance(value, str) else value
    if isinstance(v, str) and v.startswith("0x"):
        v = v[2:]
    return hex64(v, "sha256")


def find(ledger, sha256: str):
    """The first block holding this fingerprint, and the kind it was sealed as."""
    for blk in ledger.blocks():
        for r in blk.roots:
            if r.get("sha256") == sha256:
                return blk, r.get("kind")
    return None, None


def pending(requests: list[Path]) -> list[tuple[Path, dict]]:
    """The root each waiting request asks for, approved or not."""
    out = []
    for p in requests:
        try:
            out.append((p, parse_roots(loads_strict(p.read_text())["roots"])[0]))
        except (KeyError, TypeError, SchemaError, ValueError) as e:
            raise SchemaError(f"{p} is not a request: {e}")
    return out


@dataclass
class Sealed:
    index: int
    block_hash: str
    timestamp: str
    base_tx: str | None    # 0x-prefixed, None until the anchor's receipt is on disk
    ots_proof: str | None  # base64 of the block's .ots, when there is one


def sealed_facts(ledger, blk) -> Sealed:
    return Sealed(blk.index, blk.hash, blk.timestamp, _base_tx(ledger, blk), _ots_proof(ledger, blk))


def _base_tx(ledger, blk) -> str | None:
    """The anchor's transaction, only from a receipt that names this very block."""
    base = ledger.proof_path(blk.index, "base.json")
    if base.is_symlink() or not base.is_file():
        return None
    r = loads_strict(base.read_text())
    if not isinstance(r, dict) or r.get("index") != blk.index or r.get("hash") != blk.hash:
        raise SchemaError(f"{base.name} is not the receipt of block {blk.index}; nothing reported")
    t = str(r.get("tx") or "")
    return "0x" + hex64(t[2:] if t.startswith("0x") else t, f"{base.name}.tx")


def _ots_proof(ledger, blk) -> str | None:
    """Base64 of the block's .ots, only when it reads as a proof of this block, read
    the way verify reads it: never through a link, never past its size limit. Anything
    else is left out, since the app keeps the first proof it is sent."""
    from .witness import _OTS_MAX, _read_regular
    p = ledger.proof_path(blk.index, "hash.ots")
    if p.is_symlink():
        return None
    try:
        from opentimestamps.core.serialize import BytesDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
        data = _read_regular(p, _OTS_MAX + 1)
        if data is None or len(data) > _OTS_MAX:
            return None
        proof = DetachedTimestampFile.deserialize(BytesDeserializationContext(data))
    except Exception:  # missing, unreadable, not a proof, or no python-opentimestamps here
        return None
    if proof.file_digest != hashlib.sha256(bytes.fromhex(blk.hash)).digest():
        return None
    b64 = base64.b64encode(data).decode()
    return b64 if len(b64) <= OTS_MAX else None  # cut short it would be no proof at all


def verify_url(sha256: str) -> str:
    return f"{NETWORK_CHECK}?sha={sha256}"


def report_payload(rid: str | None, document: str, sha256: str, s: Sealed) -> dict:
    """What POST /api/seal receives. `document` and `sha256` let the app file the
    seal under the right document and refuse one that is not the file it holds.
    With no record id (block.yml's report: the ledger never holds one) the app finds
    the record by the fingerprint itself."""
    body = {"document": document, "sha256": sha256, "block": s.index,
            "base_tx": s.base_tx, "verify_url": verify_url(sha256)}
    if rid is not None:
        body = {"id": rid, **body}
    if s.ots_proof:
        body["ots_proof"] = s.ots_proof
    return body


def report_url(app: str) -> str:
    """https://host[:port] and nothing else: a user, a path, a query would each let the
    bearer go somewhere other than the host it reads as."""
    bad = SchemaError("--report: the app's origin, https://host, with no path")
    app = app.strip()
    try:
        u = urllib.parse.urlsplit(app)
        port = u.port
    except ValueError:
        raise bad
    if (u.scheme != "https" or not u.hostname or "@" in u.netloc or u.query or u.fragment
            or u.path not in ("", "/") or not re.match(r"^[A-Za-z0-9.-]+$", u.hostname)):
        raise bad
    return f"https://{u.hostname}" + (f":{port}" if port else "") + SEAL_PATH


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the bearer to wherever it points. Refused, never followed."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_open = urllib.request.build_opener(_NoRedirect).open


def post(url: str, secret: str, body: dict, opener=None, timeout: float = 30) -> tuple[int, str]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
        "authorization": f"Bearer {secret}", "content-type": "application/json"})
    try:
        with (opener or _open)(req, timeout=timeout) as r:
            return r.status, r.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # a refused redirect lands here too
        return e.code, e.read(2000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return 0, f"could not reach the app ({getattr(e, 'reason', e)})"
