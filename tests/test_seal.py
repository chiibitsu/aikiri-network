"""`seal`: a second document on a record, by its hash, and a repeat that changes nothing.

The flow under test is the one the app's chat drives: the agreement is sealed,
then the official invoice for the same record, each in its own block, each
reported to the app with the record id that never reaches the ledger.
"""
import base64
import json
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from aikiri_ledger import cli, seal as sealing
from aikiri_ledger.approval import ApprovalKey, SoftwareApprover
from aikiri_ledger.chain import Ledger, MANILA, new_key
from aikiri_ledger.request import Request
from aikiri_ledger.trust import Trust

RECORD = "5f0c3a52-8d1e-4f7b-9a26-0e4b7c1d2f38"
AGREEMENT = "a1" * 32
INVOICE = "b2" * 32
APP = "https://app.example"
T0 = datetime(2026, 10, 19, 9, 0, tzinfo=MANILA)


@pytest.fixture
def mac():
    return SoftwareApprover.from_seed(b"\x01" * 32, "mac")


@pytest.fixture
def sk():
    return new_key()


@pytest.fixture
def world(tmp_path, sk, mac):
    """A ledger at its genesis and an external trust file naming its validator and device."""
    L = Ledger(tmp_path / "ledger")
    g = L.init(sk, now=T0)
    trust = Trust(chain_id=8453, contract="0x" + "11" * 20, owner="0x" + "22" * 20,
                  code_keccak=None, genesis_hash=g.hash, validator=sk.verify_key.encode().hex(),
                  approval_keys=[ApprovalKey("mac", mac.public_key_hex)], legacy={0: g.hash},
                  source="external")
    tf = trust.write(tmp_path / "trust.json")
    return L, trust, tf


class App:
    """Stands in for the app's POST /api/seal: records what it was sent, answers like it."""
    def __init__(self, status=200):
        self.calls, self.status, self.seen = [], status, set()

    def __call__(self, req, timeout):
        body = json.loads(req.data)
        self.calls.append({"url": req.full_url, "auth": req.get_header("Authorization"), "body": body})
        key = (body["id"], body["document"])
        already = key in self.seen
        self.seen.add(key)
        app = self

        class R:
            status = app.status
            def read(self, n): return json.dumps({"sealed": True, "already": already}).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return R()


def run(L, tf, *argv):
    return cli.main(["--ledger", str(L.root), "--trust", str(tf), *argv])


def snapshot(L):
    return {str(p.relative_to(L.root)): p.read_bytes() for p in sorted(L.root.rglob("*")) if p.is_file()}


def ots_of(block_hash, digest=None):
    """A real .ots: pending on one calendar, of sha256(block hash) unless told otherwise."""
    import hashlib, io
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(digest or hashlib.sha256(bytes.fromhex(block_hash)).digest())
    ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    buf = io.BytesIO()
    DetachedTimestampFile(OpSHA256(), ts).serialize(StreamSerializationContext(buf))
    return buf.getvalue()


def land(L, sk, mac, n):
    """What approve + push + block.yml do: seal the waiting request, write and anchor the block."""
    req_path = L.requests_dir / "next.json"
    payload = json.loads(req_path.read_text())
    req = Request.build(index=payload["index"], prev_hash=payload["prev_hash"], roots=payload["roots"],
                        nonce=payload["nonce"], validator=payload["validator"], approver=mac)
    blk = L.append_from_request(req, sk, now=T0 + timedelta(minutes=n),
                                registered=[ApprovalKey("mac", mac.public_key_hex)])
    req_path.unlink()
    L.proof_path(blk.index, "base.json").parent.mkdir(parents=True, exist_ok=True)
    L.proof_path(blk.index, "base.json").write_text(json.dumps(
        {"index": blk.index, "hash": blk.hash, "tx": f"{blk.index:02x}" * 32}) + "\n")
    L.proof_path(blk.index, "hash.ots").write_bytes(ots_of(blk.hash))
    return blk


def test_a_second_document_on_an_existing_record(world, sk, mac, monkeypatch, capsys):
    L, trust, tf = world
    app = App()
    monkeypatch.setattr(sealing, "_open", app)
    monkeypatch.setenv(sealing.SECRET_ENV, "test-bearer")

    # The agreement, as the chat line has always been written.
    assert run(L, tf, "seal-acceptance", RECORD, AGREEMENT) == 0
    first = land(L, sk, mac, 1)
    assert first.roots == [{"kind": "acceptance", "sha256": AGREEMENT}]
    assert run(L, tf, "seal-acceptance", RECORD, AGREEMENT, "--report", APP) == 0

    # The official invoice, same record, its own block.
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0
    req = json.loads((L.requests_dir / "next.json").read_text())
    assert req["roots"] == [{"kind": "invoice", "sha256": INVOICE}]
    assert req["index"] == 2 and req["prev_hash"] == first.hash
    second = land(L, sk, mac, 2)
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE, "--report", APP) == 0

    a, i = (c["body"] for c in app.calls)
    assert a == {"id": RECORD, "document": "agreement", "sha256": AGREEMENT, "block": 1,
                 "base_tx": "0x" + "01" * 32, "verify_url": f"{sealing.NETWORK_CHECK}?sha={AGREEMENT}",
                 "ots_proof": base64.b64encode(ots_of(first.hash)).decode()}
    assert i == {"id": RECORD, "document": "invoice", "sha256": INVOICE, "block": 2,
                 "base_tx": "0x" + "02" * 32, "verify_url": f"{sealing.NETWORK_CHECK}?sha={INVOICE}",
                 "ots_proof": base64.b64encode(ots_of(second.hash)).decode()}
    assert all(c["url"] == APP + "/api/seal" and c["auth"] == "Bearer test-bearer" for c in app.calls)

    # Nothing about the record is on the ledger: a kind and a fingerprint per block.
    for blk in (first, second):
        text = (L.root / "blocks" / f"{blk.index:06d}.json").read_text()
        assert RECORD not in text and "agreement" not in text
    assert run(L, tf, "verify", "--offline", "--require", "local") == 0


def test_a_repeat_changes_nothing(world, sk, mac, monkeypatch):
    L, trust, tf = world
    app = App()
    monkeypatch.setattr(sealing, "_open", app)
    monkeypatch.setenv(sealing.SECRET_ENV, "test-bearer")

    # Requested, not yet pushed: the same line again leaves the request byte for byte.
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0
    before = snapshot(L)
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE.upper()) == 0   # a pasted variant too
    assert snapshot(L) == before

    # Sealed: no request, no block, and the report says the same thing every time.
    land(L, sk, mac, 1)
    before = snapshot(L)
    for _ in range(3):
        assert run(L, tf, "seal", "invoice", RECORD, INVOICE, "--report", APP) == 0
    assert snapshot(L) == before
    assert not list(L.requests_dir.glob("*.json"))
    assert L.head().index == 1
    bodies = [c["body"] for c in app.calls]
    assert bodies == [bodies[0]] * 3


def test_report_url_and_secret_from_the_environment(world, sk, mac, monkeypatch, capsys):
    L, trust, tf = world
    app = App()
    monkeypatch.setattr(sealing, "_open", app)
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0
    land(L, sk, mac, 1)

    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0          # no app named: nothing sent
    assert "not reported" in capsys.readouterr().out and not app.calls

    monkeypatch.setenv(sealing.URL_ENV, APP)
    with pytest.raises(SystemExit, match=sealing.SECRET_ENV):            # no bearer: nothing sent
        run(L, tf, "seal", "invoice", RECORD, INVOICE)
    assert not app.calls

    monkeypatch.setenv(sealing.SECRET_ENV, "test-bearer")
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0
    assert len(app.calls) == 1
    assert "test-bearer" not in capsys.readouterr().out


def test_a_refused_report_fails_the_command(world, sk, mac, monkeypatch):
    L, trust, tf = world
    monkeypatch.setattr(sealing, "_open", App(status=409))
    monkeypatch.setenv(sealing.SECRET_ENV, "test-bearer")
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0
    land(L, sk, mac, 1)
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE, "--report", APP) == 1


def test_no_report_before_the_base_receipt(world, sk, mac, monkeypatch):
    L, trust, tf = world
    app = App()
    monkeypatch.setattr(sealing, "_open", app)
    monkeypatch.setenv(sealing.SECRET_ENV, "test-bearer")
    assert run(L, tf, "seal", "invoice", RECORD, INVOICE) == 0
    blk = land(L, sk, mac, 1)
    L.proof_path(blk.index, "base.json").unlink()
    with pytest.raises(SystemExit, match="no Base receipt"):
        run(L, tf, "seal", "invoice", RECORD, INVOICE, "--report", APP)
    assert not app.calls


def test_one_file_is_one_document(world, sk, mac):
    L, trust, tf = world
    assert run(L, tf, "seal", "agreement", RECORD, AGREEMENT) == 0
    with pytest.raises(SystemExit, match="already asks to seal this file as acceptance"):
        run(L, tf, "seal", "invoice", RECORD, AGREEMENT)
    land(L, sk, mac, 1)
    with pytest.raises(SystemExit, match="already sealed as acceptance in block 1"):
        run(L, tf, "seal", "invoice", RECORD, AGREEMENT)
    assert not list(L.requests_dir.glob("*.json"))


def test_one_request_at_a_time(world):
    L, trust, tf = world
    assert run(L, tf, "seal", "agreement", RECORD, AGREEMENT) == 0
    before = snapshot(L)
    with pytest.raises(SystemExit, match="one block, one request"):
        run(L, tf, "seal", "invoice", RECORD, INVOICE)
    assert snapshot(L) == before


@pytest.mark.parametrize("argv", [
    ["seal", "invoice", "../etc", INVOICE],              # not a record id
    ["seal", "invoice", RECORD, "b2" * 31],              # not a fingerprint
    ["seal", "invoice", RECORD, "zz" * 32],
    ["seal-acceptance", "a" * 65, AGREEMENT],
])
def test_bad_lines_are_refused(world, argv):
    L, trust, tf = world
    with pytest.raises(SystemExit):
        run(L, tf, *argv)
    assert not L.requests_dir.exists() or not list(L.requests_dir.glob("*.json"))


def test_unknown_document_is_refused(world):
    L, trust, tf = world
    with pytest.raises(SystemExit):
        run(L, tf, "seal", "receipt", RECORD, INVOICE)


def test_report_goes_only_to_an_https_origin():
    assert sealing.report_url("https://app.example/") == "https://app.example/api/seal"
    assert sealing.report_url("https://app.example:8443") == "https://app.example:8443/api/seal"
    for bad in ("http://app.example", "https://app.example/api/seal", "https://a.example?x=1", "app.example",
                "https://app.example@evil.example", "https://user:pw@evil.example", "https://app.example#x",
                "https://app.example:99999", "https://"):
        with pytest.raises(Exception):
            sealing.report_url(bad)


def test_a_redirect_is_not_followed():
    """Following it would hand the bearer to whatever it points at."""
    hits = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append((self.path, self.headers.get("Authorization")))
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *a): pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    status, _ = sealing.post(f"http://127.0.0.1:{srv.server_port}/api/seal", "test-bearer", {"x": 1})
    t.join(5)
    srv.server_close()
    assert status == 307
    assert hits == [("/api/seal", "Bearer test-bearer")]


def report_for(L, sk, mac, monkeypatch, tamper):
    """Seal one invoice, let `tamper` change the block's proof files, report, and return what was sent."""
    app = App()
    monkeypatch.setattr(sealing, "_open", app)
    monkeypatch.setenv(sealing.SECRET_ENV, "test-bearer")
    tf = L.root.parent / "trust.json"
    assert cli.main(["--ledger", str(L.root), "--trust", str(tf), "seal", "invoice", RECORD, INVOICE]) == 0
    blk = land(L, sk, mac, 1)
    tamper(blk)
    rc = cli.main(["--ledger", str(L.root), "--trust", str(tf), "seal", "invoice", RECORD, INVOICE, "--report", APP])
    return rc, [c["body"] for c in app.calls]


def test_a_receipt_of_another_block_is_never_reported(world, sk, mac, monkeypatch):
    """A stale or copied base.json names another block: its tx does not witness this seal."""
    L, _, _ = world
    def stale(blk):
        p = L.proof_path(blk.index, "base.json")
        r = json.loads(p.read_text()); r["hash"] = "ee" * 32
        p.write_text(json.dumps(r))
    with pytest.raises(SystemExit, match="not the receipt of block 1"):
        report_for(L, sk, mac, monkeypatch, stale)


@pytest.mark.parametrize("how", ["other block", "not a proof", "link"])
def test_only_a_proof_of_this_block_is_sent(world, sk, mac, monkeypatch, tmp_path, how):
    """The app keeps the first proof it is sent, so anything else is left out, and a link
    is never read: it could point at any file on the sealing machine."""
    L, _, _ = world
    secret = tmp_path / "outside.txt"
    secret.write_text("not for the app")
    def bad(blk):
        p = L.proof_path(blk.index, "hash.ots")
        if how == "other block":
            p.write_bytes(ots_of("ee" * 32))
        elif how == "not a proof":
            p.write_bytes(b"\x00 not a timestamp")
        else:
            p.unlink(); p.symlink_to(secret)
    rc, bodies = report_for(L, sk, mac, monkeypatch, bad)
    assert rc == 0 and len(bodies) == 1
    assert "ots_proof" not in bodies[0]
    assert "not for the app" not in json.dumps(bodies)
