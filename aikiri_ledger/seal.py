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
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .canonical import hex64, loads_strict
from .errors import SchemaError
from .request import parse_roots

# document -> root kind. Add a document here, and its kind to ROOT_KINDS.
DOCUMENTS = {"agreement": "acceptance", "invoice": "invoice"}
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
    tx = None
    base = ledger.proof_path(blk.index, "base.json")
    if base.exists():
        t = str(loads_strict(base.read_text()).get("tx") or "")
        t = t[2:] if t.startswith("0x") else t
        tx = "0x" + hex64(t, f"{base.name}.tx")
    ots = None
    p = ledger.proof_path(blk.index, "hash.ots")
    if p.is_file():
        b64 = base64.b64encode(p.read_bytes()).decode()
        ots = b64 if len(b64) <= OTS_MAX else None  # cut short it would be no proof at all
    return Sealed(blk.index, blk.hash, blk.timestamp, tx, ots)


def verify_url(sha256: str) -> str:
    return f"{NETWORK_CHECK}?sha={sha256}"


def report_payload(rid: str, document: str, sha256: str, s: Sealed) -> dict:
    """What POST /api/seal receives. `document` and `sha256` let the app file the
    seal under the right document and refuse one that is not the file it holds."""
    body = {"id": rid, "document": document, "sha256": sha256, "block": s.index,
            "base_tx": s.base_tx, "verify_url": verify_url(sha256)}
    if s.ots_proof:
        body["ots_proof"] = s.ots_proof
    return body


def report_url(app: str) -> str:
    app = app.strip().rstrip("/")
    if not re.match(r"^https://[^\s/?#]+$", app):
        raise SchemaError("--report: the app's origin, https://host, with no path")
    return app + SEAL_PATH


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
