"""Format v2, human approval, external trust, strict verification.

The v2 tests fail before the v2 work and pass after; the proof-upkeep tests
cover the Bitcoin proofs. Blocks 0 and 1, the v1 blocks, are never rewritten:
they verify as v1 against pinned hashes.
"""
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from web3 import Web3, EthereumTesterProvider

from aikiri_ledger.chain import Ledger, Block, new_key, MANILA
from aikiri_ledger.canonical import (canonical_bytes, domain_hash, loads_strict, strict, hex64,
                                     BLOCK_DOMAIN_V2, APPROVAL_DOMAIN_V1)
from aikiri_ledger.errors import SchemaError, TrustError
from aikiri_ledger.approval import ApprovalKey, SoftwareApprover, approval_message, verify_approval
from aikiri_ledger.request import Request
from aikiri_ledger.trust import Trust
from aikiri_ledger.verify import State, verify_chain, verify_all
from aikiri_ledger.witness import compile_contract, BaseWitness, QuorumBase, QuorumError

VECTORS = json.loads((Path(__file__).parent / "vectors" / "v2_blocks.json").read_text())
LEGACY = json.loads((Path(__file__).parent / "vectors" / "v1_legacy.json").read_text())
JOURNAL_SHA = "77b40243ddbfb10be8bf36ee8d4e895228a88a68a842c1ffee8166a3656e41c1"


# ------------------------------------------------------------------ fixtures ----
@pytest.fixture
def mac():
    return SoftwareApprover.from_seed(b"\x01" * 32, "mac")


@pytest.fixture
def iphone():
    return SoftwareApprover.from_seed(b"\x02" * 32, "iphone")


@pytest.fixture
def stranger():
    return SoftwareApprover.from_seed(b"\x03" * 32, "stranger-mac")


@pytest.fixture
def sk():
    return new_key()


@pytest.fixture
def registered(mac, iphone):
    return [ApprovalKey("mac", mac.public_key_hex), ApprovalKey("iphone", iphone.public_key_hex)]


@pytest.fixture
def trust(sk, registered, tmp_path):
    """An external trust anchor: supplied to the verifier, not read from the repo."""
    return Trust(chain_id=8453, contract="0x" + "11" * 20, owner="0x" + "22" * 20,
                 code_keccak=None, genesis_hash=None, validator=sk.verify_key.encode().hex(),
                 approval_keys=registered, legacy={}, source="external")


@pytest.fixture
def ledger(tmp_path, sk, trust):
    L = Ledger(tmp_path / "ledger")
    g = L.init(sk, now=datetime(2026, 9, 2, 4, 43, tzinfo=MANILA))
    trust.genesis_hash = g.hash
    trust.legacy = {0: g.hash}
    return L


def make_request(ledger, sk, approver, *, kind="journal", sha256=JOURNAL_SHA, index=None,
                 prev_hash=None, nonce="cc" * 32):
    head = ledger.head()
    return Request.build(index=index if index is not None else head.index + 1,
                         prev_hash=prev_hash or head.hash,
                         roots=[{"kind": kind, "sha256": sha256}],
                         nonce=nonce, validator=sk.verify_key.encode().hex(),
                         approver=approver)


# --------------------------------------------------------- canonical + vectors ----
def test_golden_vectors_exact_bytes_and_hashes():
    """The committed bytes are the protocol. A change here is a version change."""
    for v in VECTORS["vectors"]:
        body = {k: val for k, val in v["block"].items() if k not in ("signature", "hash")}
        assert canonical_bytes(body).decode() == v["canonical"], v["name"]
        assert domain_hash(BLOCK_DOMAIN_V2, body) == v["hash"], v["name"]


def test_golden_approval_message_bytes():
    a = VECTORS["approval_message"]
    msg = approval_message(index=a["index"], prev_hash=a["prev_hash"], roots=a["roots"],
                           nonce=a["nonce"], validator=a["validator"])
    assert msg.decode() == a["message_utf8"]
    assert msg.startswith(APPROVAL_DOMAIN_V1)


def test_canonical_is_ascii_and_rejects_nan_and_infinity():
    assert b"\\u00e9" in canonical_bytes({"k": "é"})  # escaped, never raw UTF-8
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical_bytes({"k": bad})
    for text in ('{"k": NaN}', '{"k": Infinity}', '{"k": -Infinity}'):
        with pytest.raises(SchemaError):
            loads_strict(text)


def test_strict_rejects_unknown_and_missing_keys():
    assert strict({"a": 1, "b": 2}, ("a", "b"), "thing") == {"a": 1, "b": 2}
    with pytest.raises(SchemaError):
        strict({"a": 1, "b": 2, "c": 3}, ("a", "b"), "thing")
    with pytest.raises(SchemaError):
        strict({"a": 1}, ("a", "b"), "thing")
    with pytest.raises(SchemaError):
        strict([], ("a",), "thing")


def test_hex64_rejects_uppercase_and_wrong_length():
    assert hex64("a" * 64, "f") == "a" * 64
    for bad in ("A" * 64, "a" * 63, "a" * 65, "g" * 64, 1, None):
        with pytest.raises(SchemaError):
            hex64(bad, "f")


# ------------------------------------------------------------------- approval ----
def test_approval_roundtrip_and_wrong_device_rejected(mac, stranger, registered):
    args = dict(index=2, prev_hash="ab" * 32, roots=[{"kind": "journal", "sha256": JOURNAL_SHA}],
                nonce="cc" * 32, validator="d1" * 32)
    ok, why = verify_approval(mac.approve(**args), registered=registered, **args)
    assert ok, why
    ok, why = verify_approval(stranger.approve(**args), registered=registered, **args)
    assert not ok and "not a registered" in why.lower()


def test_approval_is_bound_to_every_field(mac, registered):
    args = dict(index=2, prev_hash="ab" * 32, roots=[{"kind": "journal", "sha256": JOURNAL_SHA}],
                nonce="cc" * 32, validator="d1" * 32)
    approval = mac.approve(**args)
    for field, other in [("index", 3), ("prev_hash", "cd" * 32), ("nonce", "dd" * 32),
                         ("validator", "d2" * 32),
                         ("roots", [{"kind": "journal", "sha256": "ff" * 32}])]:
        ok, _ = verify_approval(approval, registered=registered, **{**args, field: other})
        assert not ok, f"approval must not survive a changed {field}"


def test_approval_device_label_cannot_borrow_another_keys_trust(mac, iphone, registered):
    """A signature from the mac key presented under the iphone's label is refused."""
    args = dict(index=2, prev_hash="ab" * 32, roots=[{"kind": "journal", "sha256": JOURNAL_SHA}],
                nonce="cc" * 32, validator="d1" * 32)
    a = dict(mac.approve(**args))
    a["device"] = "iphone"
    ok, why = verify_approval(a, registered=registered, **args)
    assert not ok and "device" in why.lower()


def test_either_registered_device_approves(mac, iphone, registered):
    """One device lost, the other still writes blocks."""
    args = dict(index=2, prev_hash="ab" * 32, roots=[{"kind": "journal", "sha256": JOURNAL_SHA}],
                nonce="cc" * 32, validator="d1" * 32)
    for who in (mac, iphone):
        ok, why = verify_approval(who.approve(**args), registered=registered, **args)
        assert ok, why


def test_secure_enclave_key_and_signature_shapes(mac):
    """P-256 X9.62 uncompressed public key and DER ECDSA signature: what the enclave emits."""
    assert mac.public_key_hex.startswith("04") and len(mac.public_key_hex) == 130
    a = mac.approve(index=2, prev_hash="ab" * 32, roots=[{"kind": "journal", "sha256": JOURNAL_SHA}],
                    nonce="cc" * 32, validator="d1" * 32)
    assert set(a) == {"device", "pubkey", "sig"}
    assert bytes.fromhex(a["sig"])[0] == 0x30  # DER SEQUENCE


# -------------------------------------------------------------------- request ----
def test_request_schema_is_closed(ledger, sk, mac):
    r = make_request(ledger, sk, mac)
    d = json.loads(r.to_json())
    assert set(d) == {"v", "index", "prev_hash", "roots", "nonce", "validator", "approval"}
    for bad in [{**d, "content": "FULL JOURNAL TEXT"},
                {**d, "roots": [{**d["roots"][0], "ref": "03_human/journal/decision-journal.md"}]},
                {**d, "roots": [{**d["roots"][0], "content": "text"}]},
                {**d, "roots": []},
                {**d, "roots": [d["roots"][0], d["roots"][0]]},
                {**d, "roots": [{"kind": "not-a-kind", "sha256": JOURNAL_SHA}]}]:
        with pytest.raises(SchemaError):
            Request.parse(json.dumps(bad))


def test_request_refused_when_it_does_not_match_the_head(ledger, sk, mac, registered):
    good = make_request(ledger, sk, mac)
    ledger.consume(good)  # must not raise
    wrong_index = make_request(ledger, sk, mac, index=99)
    with pytest.raises(ValueError):
        ledger.consume(wrong_index)
    wrong_prev = make_request(ledger, sk, mac, prev_hash="ff" * 32)
    with pytest.raises(ValueError):
        ledger.consume(wrong_prev)


def test_request_consumed_exactly_once(ledger, sk, mac):
    r = make_request(ledger, sk, mac)
    ledger.append_from_request(r, sk, now=datetime(2026, 9, 3, tzinfo=MANILA))
    r2 = make_request(ledger, sk, mac, nonce="cc" * 32)  # same nonce, next index
    with pytest.raises(ValueError):
        ledger.append_from_request(r2, sk, now=datetime(2026, 9, 4, tzinfo=MANILA))


def test_block_refuses_a_request_without_valid_approval(ledger, sk, stranger, mac):
    r = make_request(ledger, sk, stranger)
    with pytest.raises(ValueError):
        ledger.append_from_request(r, sk, now=datetime(2026, 9, 3, tzinfo=MANILA),
                                   registered=[ApprovalKey("mac", mac.public_key_hex)])


def test_no_queue_file_is_ever_read(ledger, sk, mac):
    """The queue is gone. A stray queue.json cannot become a block."""
    (ledger.root / "queue.json").write_text(json.dumps([{"kind": "journal", "sha256": "ab" * 32}]))
    assert not hasattr(ledger, "queue")
    r = make_request(ledger, sk, mac)
    b = ledger.append_from_request(r, sk, now=datetime(2026, 9, 3, tzinfo=MANILA))
    assert [x["sha256"] for x in b.roots] == [JOURNAL_SHA]


# ---------------------------------------------------------------------- block ----
def test_block_v2_shape_has_no_ref_and_no_merkle_root(ledger, sk, mac):
    b = ledger.append_from_request(make_request(ledger, sk, mac), sk,
                                   now=datetime(2026, 9, 3, tzinfo=MANILA))
    d = json.loads((ledger.blocks_dir / "000001.json").read_text())
    assert set(d) == {"v", "index", "timestamp", "prev_hash", "roots", "nonce",
                      "approval", "validator", "signature", "hash"}
    assert d["v"] == 2 and set(d["roots"][0]) == {"kind", "sha256"}
    assert "merkle_root" not in d and "ref" not in json.dumps(d)
    assert b.hash == domain_hash(BLOCK_DOMAIN_V2, {k: v for k, v in d.items()
                                                   if k not in ("signature", "hash")})


def test_approval_is_covered_by_the_block_hash(ledger, sk, mac, iphone):
    """Stripping or swapping the approval breaks the hash and the validator signature."""
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    p = ledger.blocks_dir / "000001.json"
    d = json.loads(p.read_text())
    del d["approval"]
    p.write_text(json.dumps(d))
    with pytest.raises(SchemaError):
        Block.parse(p.read_text())


def test_block_rejects_unknown_top_level_field(ledger, sk, mac):
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    p = ledger.blocks_dir / "000001.json"
    d = json.loads(p.read_text())
    d["content"] = "FULL JOURNAL TEXT HERE"
    p.write_text(json.dumps(d))
    with pytest.raises(SchemaError):
        Block.parse(p.read_text())


def test_v1_accepted_only_for_the_pinned_prefix(tmp_path, sk, trust):
    """Blocks 0 and 1 keep their exact bytes. A v1-shaped block 2 is refused."""
    L = Ledger(tmp_path / "ledger")
    L.blocks_dir.mkdir(parents=True)
    for b in LEGACY["blocks"]:
        (L.blocks_dir / f"{b['index']:06d}.json").write_text(Path(b["file"]).read_text())
    head = LEGACY["blocks"][-1]
    L.head_path.write_text(f"{head['index']} {head['hash']}\n")
    t = Trust(chain_id=8453, contract="0x" + "11" * 20, owner="0x" + "22" * 20, code_keccak=None,
              genesis_hash=LEGACY["blocks"][0]["hash"], validator=LEGACY["blocks"][0]["validator"],
              approval_keys=[], legacy={b["index"]: b["hash"] for b in LEGACY["blocks"]},
              source="external")
    state, report = verify_chain(L, t)
    assert state >= State.VALID_LOCALLY, report

    forged = json.loads((L.blocks_dir / "000001.json").read_text())
    forged["index"] = 2
    forged["prev_hash"] = head["hash"]
    (L.blocks_dir / "000002.json").write_text(json.dumps(forged, indent=2, sort_keys=True))
    L.head_path.write_text(f"2 {forged['hash']}\n")
    state, report = verify_chain(L, t)
    assert state == State.INVALID and any("v1" in r or "version" in r for r in report)


def test_live_blocks_zero_and_one_are_byte_identical_to_the_repo(tmp_path):
    """Nothing in this change may alter what is already anchored."""
    for b in LEGACY["blocks"]:
        raw = Path(b["file"]).read_bytes()
        assert Block.parse(raw.decode()).hash == b["hash"]
        assert json.loads(raw)["hash"] == b["hash"]


# ----------------------------------------------------------- chain-level rules ----
def test_timestamps_must_strictly_increase(ledger, sk, mac, trust):
    t0 = datetime(2026, 9, 3, tzinfo=MANILA)
    ledger.append_from_request(make_request(ledger, sk, mac), sk, now=t0)
    r2 = make_request(ledger, sk, mac, nonce="dd" * 32)
    with pytest.raises(ValueError):
        ledger.append_from_request(r2, sk, now=t0 - timedelta(seconds=1))


def test_nonce_replay_across_the_chain_is_caught_by_verify(ledger, sk, mac, trust):
    ledger.append_from_request(make_request(ledger, sk, mac), sk, now=datetime(2026, 9, 3, tzinfo=MANILA))
    ledger.append_from_request(make_request(ledger, sk, mac, nonce="dd" * 32), sk,
                               now=datetime(2026, 9, 4, tzinfo=MANILA))
    p = ledger.blocks_dir / "000002.json"
    d = json.loads(p.read_text())
    d["nonce"] = "cc" * 32
    p.write_text(json.dumps(d, indent=2, sort_keys=True))
    state, report = verify_chain(ledger, trust)
    assert state == State.INVALID and any("nonce" in r for r in report)


def test_validator_continuity_pinned_to_trust(ledger, sk, mac, trust, registered):
    """A block signed by any other key is invalid, with or without a witness."""
    other = new_key()
    r = Request.build(index=1, prev_hash=ledger.head().hash,
                      roots=[{"kind": "journal", "sha256": JOURNAL_SHA}], nonce="ee" * 32,
                      validator=other.verify_key.encode().hex(), approver=mac)
    ledger.append_from_request(r, other, now=datetime(2026, 9, 3, tzinfo=MANILA))
    state, report = verify_chain(ledger, trust)
    assert state == State.INVALID and any("validator" in r for r in report)


def test_verify_rejects_a_block_whose_approval_key_is_not_in_trust(ledger, sk, stranger, trust):
    r = make_request(ledger, sk, stranger)
    ledger.append_from_request(r, sk, now=datetime(2026, 9, 3, tzinfo=MANILA), registered=None)
    state, report = verify_chain(ledger, trust)
    assert state == State.INVALID and any("approval" in r for r in report)


# ------------------------------------------------------------- trust anchoring ----
def test_repo_defaults_are_not_an_anchor(ledger, sk, mac, monkeypatch):
    """Whoever can rewrite the ledger can rewrite the repo. Repo pins cap the state."""
    t = Trust.from_repo_defaults()
    assert t.source == "repo" and not t.is_external
    state, report = verify_all(ledger, t)
    assert state <= State.VALID_LOCALLY
    assert any("not an independent" in r.lower() or "repo" in r.lower() for r in report)


def test_external_trust_file_loads_and_signature_is_checked(tmp_path, mac, iphone, sk, registered):
    body = {"v": 1, "chainId": 8453, "contract": "0x" + "11" * 20, "owner": "0x" + "22" * 20,
            "code_keccak": None, "genesis_hash": "ab" * 32, "validator": sk.verify_key.encode().hex(),
            "approval_keys": [{"device": k.device, "pubkey": k.pubkey} for k in registered],
            "legacy": {"0": "ab" * 32}}
    signed = {"trust": body, "sig": mac.sign_trust(body)}
    p = tmp_path / "trust.json"
    p.write_text(json.dumps(signed))
    t = Trust.load(p)
    assert t.is_external and t.source == "external-signed" and len(t.approval_keys) == 2

    tampered = json.loads(p.read_text())
    tampered["trust"]["validator"] = "ff" * 32
    p.write_text(json.dumps(tampered))
    with pytest.raises(TrustError):
        Trust.load(p)


def test_unsigned_external_trust_is_accepted_but_labelled(tmp_path, sk, registered):
    body = {"v": 1, "chainId": 8453, "contract": "0x" + "11" * 20, "owner": "0x" + "22" * 20,
            "code_keccak": None, "genesis_hash": "ab" * 32, "validator": sk.verify_key.encode().hex(),
            "approval_keys": [{"device": k.device, "pubkey": k.pubkey} for k in registered],
            "legacy": {}}
    p = tmp_path / "trust.json"
    p.write_text(json.dumps({"trust": body}))
    t = Trust.load(p)
    assert t.is_external and t.source == "external-unsigned"


# --------------------------------------------------------------------- states ----
def test_four_states_and_no_verified_without_witnesses(ledger, sk, mac, trust):
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    state, report = verify_all(ledger, trust)
    assert state == State.VALID_LOCALLY
    assert "NOT WITNESSED" in State.text(state)
    assert "FULLY VERIFIED" not in "\n".join(report)


def test_state_text_is_exactly_the_four_rulings():
    assert State.text(State.INVALID) == "INVALID"
    assert State.text(State.VALID_LOCALLY) == "VALID LOCALLY — NOT WITNESSED"
    assert State.text(State.BASE_VERIFIED) == "BASE VERIFIED — BITCOIN PENDING"
    assert State.text(State.FULLY_VERIFIED) == "FULLY VERIFIED"


def test_trailing_unanchored_block_never_reaches_verified(ledger, sk, mac, trust):
    w3 = Web3(EthereumTesterProvider())
    c = compile_contract()
    bw = BaseWitness(w3, None, c["abi"], account=w3.eth.accounts[0])
    addr = bw.deploy(ledger.read(0).hash, c["bytecode"])
    trust.contract, trust.owner, trust.genesis_hash = addr, w3.eth.accounts[0], ledger.read(0).hash
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    state, report = verify_all(ledger, trust, base=bw)  # block 1 not anchored
    assert state <= State.VALID_LOCALLY
    assert any("not anchored" in r.lower() or "latestindex" in r.lower() for r in report)


def test_failed_bitcoin_proof_is_a_failure_not_a_shrug(ledger, sk, mac, trust):
    class FailingBtc:
        def verify(self, b):
            return False, "Bad attestation"
    state, report = verify_all(ledger, trust, bitcoin=FailingBtc())
    assert state == State.INVALID and any("bitcoin" in r.lower() for r in report)


def test_truncated_chain_fails_against_contract_latest_index(ledger, sk, mac, trust):
    w3 = Web3(EthereumTesterProvider())
    c = compile_contract()
    bw = BaseWitness(w3, None, c["abi"], account=w3.eth.accounts[0])
    addr = bw.deploy(ledger.read(0).hash, c["bytecode"])
    trust.contract, trust.owner, trust.genesis_hash = addr, w3.eth.accounts[0], ledger.read(0).hash
    b1 = ledger.append_from_request(make_request(ledger, sk, mac), sk,
                                    now=datetime(2026, 9, 3, tzinfo=MANILA))
    bw.anchor(b1)
    (ledger.blocks_dir / "000001.json").unlink()
    ledger.head_path.write_text(f"0 {ledger.read(0).hash}\n")
    state, report = verify_all(ledger, trust, base=bw)
    assert state == State.INVALID and any("latestindex" in r.lower() or "truncat" in r.lower()
                                          for r in report)


def test_contract_identity_is_pinned(ledger, sk, mac, trust):
    w3 = Web3(EthereumTesterProvider())
    c = compile_contract()
    bw = BaseWitness(w3, None, c["abi"], account=w3.eth.accounts[0])
    bw.deploy(ledger.read(0).hash, c["bytecode"])
    trust.genesis_hash = ledger.read(0).hash
    trust.contract = "0x" + "99" * 20  # not the contract we are talking to
    trust.owner = w3.eth.accounts[0]
    state, report = verify_all(ledger, trust, base=bw)
    assert state == State.INVALID and any("contract" in r.lower() for r in report)


def test_lying_base_adapter_is_caught_by_the_pins(ledger, sk, mac, trust):
    class Liar:
        address = "0x" + "11" * 20
        def matches(self, b): return True
        def latest_index(self): return 99
        def genesis_hash(self): return "ff" * 32
        def owner(self): return "0x" + "22" * 20
        def record(self, i): return {"blockHash": "ff" * 32, "anchoredAt": 0, "by": "0x" + "22" * 20}
    state, report = verify_all(ledger, trust, base=Liar())
    assert state == State.INVALID


def test_anchored_at_may_not_precede_the_block_timestamp(ledger, sk, mac, trust):
    class Backdater:
        address = None
        def matches(self, b): return True
        def latest_index(self): return 1
        def genesis_hash(self): return None
        def owner(self): return None
        def record(self, i): return {"blockHash": None, "anchoredAt": 1, "by": None}
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    state, report = verify_all(ledger, trust, base=Backdater())
    assert state == State.INVALID and any("anchoredat" in r.lower() for r in report)


# --------------------------------------------------------------- rpc quorum ----
def test_quorum_needs_a_majority_and_a_common_block():
    class R:
        def __init__(self, idx, finalized=100, ok=True):
            self._i, self.finalized, self._ok = idx, finalized, ok
        def latest_index(self, block=None): return self._i
        def matches(self, b, block=None): return self._ok
        def finalized_block(self): return self.finalized
    q = QuorumBase([R(1), R(1), R(1)])
    assert q.latest_index() == 1
    assert q.common_block() == 100


def test_quorum_disagreement_is_never_success():
    class R:
        def __init__(self, idx):
            self._i = idx
        def latest_index(self, block=None): return self._i
        def matches(self, b, block=None): return True
        def finalized_block(self): return 100
    with pytest.raises(QuorumError):
        QuorumBase([R(1), R(2), R(1)]).latest_index()


def test_quorum_tolerates_one_dead_endpoint_but_not_two():
    class Dead:
        def latest_index(self, block=None): raise ConnectionError("down")
        def matches(self, b, block=None): raise ConnectionError("down")
        def finalized_block(self): raise ConnectionError("down")
    class Live:
        def latest_index(self, block=None): return 1
        def matches(self, b, block=None): return True
        def finalized_block(self): return 100
    assert QuorumBase([Live(), Live(), Dead()]).latest_index() == 1
    with pytest.raises(QuorumError):
        QuorumBase([Live(), Dead(), Dead()]).latest_index()


# ------------------------------------------------------ broadcast / reconcile ----
def test_pending_marker_written_before_broadcast_and_cleared_after(ledger, sk, mac, tmp_path):
    """Receipt lookup can time out. The marker means the next run reconciles, never re-sends."""
    w3 = Web3(EthereumTesterProvider())
    c = compile_contract()
    bw = BaseWitness(w3, None, c["abi"], account=w3.eth.accounts[0])
    bw.deploy(ledger.read(0).hash, c["bytecode"])
    b1 = ledger.append_from_request(make_request(ledger, sk, mac), sk,
                                    now=datetime(2026, 9, 3, tzinfo=MANILA))
    seen = {}

    def watcher(path):
        seen["pending"] = path.exists()
    ledger.anchor_with_marker(bw, b1, on_broadcast=watcher)
    assert seen["pending"] is True
    assert not ledger.pending_path(1).exists()
    assert ledger.proof_path(1, "base.json").exists()


def test_reconcile_completes_a_timed_out_anchor_without_resending(ledger, sk, mac):
    w3 = Web3(EthereumTesterProvider())
    c = compile_contract()
    bw = BaseWitness(w3, None, c["abi"], account=w3.eth.accounts[0])
    bw.deploy(ledger.read(0).hash, c["bytecode"])
    b1 = ledger.append_from_request(make_request(ledger, sk, mac), sk,
                                    now=datetime(2026, 9, 3, tzinfo=MANILA))
    tx = bw.anchor(b1)  # broadcast succeeded
    ledger.write_pending(1, tx, bw.account)  # receipt lookup "timed out"
    before = w3.eth.get_transaction_count(bw.account)
    done = ledger.reconcile(bw)
    assert done == [1]
    assert w3.eth.get_transaction_count(bw.account) == before  # nothing re-sent
    assert ledger.proof_path(1, "base.json").exists() and not ledger.pending_path(1).exists()


def test_anchor_refuses_while_a_pending_marker_exists(ledger, sk, mac):
    w3 = Web3(EthereumTesterProvider())
    c = compile_contract()
    bw = BaseWitness(w3, None, c["abi"], account=w3.eth.accounts[0])
    bw.deploy(ledger.read(0).hash, c["bytecode"])
    b1 = ledger.append_from_request(make_request(ledger, sk, mac), sk,
                                    now=datetime(2026, 9, 3, tzinfo=MANILA))
    ledger.write_pending(1, "ab" * 32, bw.account)
    with pytest.raises(RuntimeError):
        ledger.anchor_with_marker(bw, b1)


# ------------------------------------------------------------------- proofs/ ----
def test_proofs_live_beside_blocks_not_among_them(ledger, sk, mac):
    w3 = Web3(EthereumTesterProvider())
    c = compile_contract()
    bw = BaseWitness(w3, None, c["abi"], account=w3.eth.accounts[0])
    bw.deploy(ledger.read(0).hash, c["bytecode"])
    b1 = ledger.append_from_request(make_request(ledger, sk, mac), sk,
                                    now=datetime(2026, 9, 3, tzinfo=MANILA))
    ledger.anchor_with_marker(bw, b1)
    assert sorted(p.name for p in ledger.blocks_dir.iterdir()) == ["000000.json", "000001.json"]
    assert (ledger.root / "proofs" / "000001.base.json").exists()


# --------------------------------------------------------------- workflows ----
def test_workflows_are_locked():
    """Phase A, asserted in code so it cannot quietly regress."""
    import re
    wf = Path(".github/workflows")
    privileged = ["block.yml", "nightly.yml", "deploy.yml", "genesis.yml"]
    for name in privileged:
        text = (wf / name).read_text()
        assert "environment:" in text, f"{name}: privileged job needs an environment gate"
        assert re.search(r"branches:\s*\[\s*main\s*\]", text), f"{name}: push must be main-only"
        assert ".github/requests/" not in text, f"{name}: request-file trigger must be gone"
    for f in wf.glob("*.yml"):
        text = f.read_text()
        assert not re.search(r"uses:.*@v\d+\s*$", text, re.M), f"{f.name}: actions must be SHA-pinned"
        for line in text.splitlines():
            if "${{" in line and ("inputs." in line or "github.event" in line):
                assert ":" in line.split("${{")[0], f"{f.name}: no untrusted interpolation in run"
    assert "AIKIRI_GARDEN_TOKEN" not in "\n".join(f.read_text() for f in wf.glob("*.yml")), \
        "the public repo must hold no vault credential"


def test_nightly_workflow_is_gone_and_replaced_by_request_driven_block():
    wf = Path(".github/workflows")
    text = (wf / "block.yml").read_text()
    assert "ledger/requests/" in text, "blocks are driven by a sealed request pushed from the vault"
    assert "queue.json" not in text


# ------------------------------------------------- approval key held in a file ----
def test_softkey_roundtrip_and_wrong_passphrase(tmp_path):
    from aikiri_ledger import softkey
    kf = tmp_path / "approval-mac.key"
    pub = softkey.create(kf, "mac", "correct horse battery staple")
    assert pub.startswith("04") and len(pub) == 130
    a = softkey.load(kf, "correct horse battery staple")
    assert a.public_key_hex == pub and a.device == "mac"
    with pytest.raises(softkey.BadPassphrase):
        softkey.load(kf, "wrong passphrase entirely")
    with pytest.raises(FileExistsError):
        softkey.create(kf, "mac", "another one")


def test_softkey_file_holds_no_usable_key_material(tmp_path):
    from aikiri_ledger import softkey
    from cryptography.hazmat.primitives import serialization
    kf = tmp_path / "k.key"
    softkey.create(kf, "mac", "correct horse battery staple")
    text = kf.read_text()
    sk = softkey.load(kf, "correct horse battery staple")._sk
    raw = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    assert raw.hex() not in text
    assert oct(kf.stat().st_mode & 0o777) == "0o600"


def test_softkey_file_is_tamper_evident(tmp_path):
    """Swapping the recorded public key must not silently sign with another key."""
    from aikiri_ledger import softkey
    kf = tmp_path / "k.key"
    softkey.create(kf, "mac", "correct horse battery staple")
    d = json.loads(kf.read_text())
    d["pubkey"] = "04" + "cd" * 64
    kf.write_text(json.dumps(d))
    with pytest.raises(softkey.BadPassphrase):
        softkey.load(kf, "correct horse battery staple")

    # From a clean file, so the device label is what fails and not the forged pubkey.
    kf2 = tmp_path / "k2.key"
    softkey.create(kf2, "mac", "correct horse battery staple")
    d = json.loads(kf2.read_text())
    d["device"] = "iphone"
    kf2.write_text(json.dumps(d))
    with pytest.raises(softkey.BadPassphrase):
        softkey.load(kf2, "correct horse battery staple")


def test_softkey_signs_a_block_the_verifier_accepts(tmp_path, ledger, sk, trust):
    """A file-held key and an enclave key are the same thing to the verifier."""
    from aikiri_ledger import softkey
    kf = tmp_path / "k.key"
    pub = softkey.create(kf, "mac", "correct horse battery staple")
    approver = softkey.load(kf, "correct horse battery staple")
    trust.approval_keys = [ApprovalKey("mac", pub)]

    head = ledger.head()
    r = Request.build(index=head.index + 1, prev_hash=head.hash,
                      roots=[{"kind": "journal", "sha256": JOURNAL_SHA}], nonce="ab" * 32,
                      validator=sk.verify_key.encode().hex(), approver=approver)
    ledger.append_from_request(r, sk, now=datetime(2026, 9, 3, tzinfo=MANILA),
                               registered=trust.approval_keys)
    state, report = verify_chain(ledger, trust)
    assert state == State.VALID_LOCALLY, report

    trust.approval_keys = [ApprovalKey("mac", SoftwareApprover.from_seed(b"\x09" * 32,
                                                                        "mac").public_key_hex)]
    state, report = verify_chain(ledger, trust)
    assert state == State.INVALID and any("approval" in x for x in report)


def test_cli_approve_keygen_refuses_the_repository(monkeypatch, tmp_path):
    from aikiri_ledger import cli
    monkeypatch.chdir(Path(__file__).resolve().parent.parent)
    with pytest.raises(SystemExit):
        cli.main(["approve-keygen", "--keyfile", "ledger/approval.key"])
    assert not Path("ledger/approval.key").exists()


def test_cli_approve_seals_a_request(monkeypatch, tmp_path, ledger, sk, trust):
    from aikiri_ledger import cli, softkey
    kf = tmp_path / "k.key"
    pub = softkey.create(kf, "mac", "correct horse battery staple")
    head = ledger.head()
    payload = Request.unsigned(index=head.index + 1, prev_hash=head.hash,
                               roots=[{"kind": "journal", "sha256": JOURNAL_SHA}],
                               validator=sk.verify_key.encode().hex())
    req_path = tmp_path / "next.json"
    req_path.write_text(json.dumps(payload, indent=2))
    monkeypatch.setattr("getpass.getpass", lambda *_: "correct horse battery staple")
    assert cli.main(["--ledger", str(ledger.root), "approve", str(req_path),
                     "--keyfile", str(kf)]) == 0
    sealed = Request.parse(req_path.read_text())
    ok, why = sealed.verify([ApprovalKey("mac", pub)])
    assert ok, why
    assert sealed.nonce == payload["nonce"] and sealed.index == payload["index"]


# ------------------------------------------------- review findings, PR #2 ----
# CodeRabbit's read of the v2 branch. Each of these fails before the fix commit.

def test_a_supplied_nonce_must_be_a_nonce(sk, mac):
    """`nonce or new_nonce()` signs whatever it is handed and turns "" into a fresh
    one silently. A nonce is the thing that makes a request unrepeatable; it is not
    a field to be lenient about."""
    roots = [{"kind": "journal", "sha256": JOURNAL_SHA}]
    validator = sk.verify_key.encode().hex()
    for bad in ("short", "zz" * 32, "AB" * 32, 1, None.__class__):
        with pytest.raises(SchemaError):
            Request.build(index=1, prev_hash="00" * 32, roots=roots,
                          validator=validator, approver=mac, nonce=bad)
        with pytest.raises(SchemaError):
            Request.unsigned(index=1, prev_hash="00" * 32, roots=roots,
                             validator=validator, nonce=bad)
    with pytest.raises(SchemaError):
        Request.unsigned(index=1, prev_hash="00" * 32, roots=roots,
                         validator=validator, nonce="")


def test_a_bad_legacy_key_is_a_trust_error(tmp_path):
    """Every refusal to load a trust file must arrive as TrustError. `int(i)` raised
    ValueError straight past the contract, and accepted keys that do not round-trip."""
    from aikiri_ledger.trust import REPO_DEFAULTS
    for bad in ("one", " 1", "+1", "1_0", "01", "-1", "1.0", ""):
        body = dict(REPO_DEFAULTS, legacy={bad: "ab" * 32})
        p = tmp_path / "t.json"
        p.write_text(json.dumps({"trust": body}))
        with pytest.raises(TrustError):
            Trust.load(p)


def test_trust_pins_must_have_the_shape_they_are_compared_against(tmp_path):
    """A pin of the wrong type is a broken anchor, not a value to compare later."""
    from aikiri_ledger.trust import REPO_DEFAULTS
    for field, bad in (("validator", 123), ("genesis_hash", "nope"), ("contract", 5),
                       ("owner", ["0x" + "11" * 20]), ("code_keccak", "xy" * 32)):
        p = tmp_path / "t.json"
        p.write_text(json.dumps({"trust": dict(REPO_DEFAULTS, **{field: bad})}))
        with pytest.raises(TrustError):
            Trust.load(p)


def test_a_quorum_without_a_common_height_is_not_a_success():
    """Readers that cannot agree on a height must not each answer at their own head.
    Silently dropping the common block is the guarantee quietly going away."""
    reads = []

    class Live:
        def latest_index(self, block=None):
            reads.append(block)
            return 1
        def matches(self, b, block=None):
            reads.append(block)
            return True
        def finalized_block(self): raise ConnectionError("no finalized tag")
    with pytest.raises(QuorumError):
        QuorumBase([Live(), Live(), Live()]).latest_index()
    with pytest.raises(QuorumError):
        QuorumBase([Live(), Live(), Live()]).matches(object())
    assert reads == [], f"read at a height nobody agreed on: {reads}"


def test_a_node_that_cannot_report_finality_does_not_vote_on_it():
    """Returning the head for `finalized` calls a reorgable height final."""
    w3 = Web3(EthereumTesterProvider())
    bw = BaseWitness(w3, None, compile_contract()["abi"], account=w3.eth.accounts[0])

    class NoTag:
        def get_block(self, tag): raise ValueError("unknown block tag")
        block_number = 999
    bw.w3 = type("W3", (), {"eth": NoTag()})()
    with pytest.raises(Exception) as e:
        bw.finalized_block()
    assert not isinstance(e.value, AssertionError)


def test_a_pending_marker_is_created_exclusively(ledger, sk, mac):
    """Two runs both pass an `exists()` check before either writes, and both send.
    Creating the marker must be the thing that decides, not a check before it."""
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    ledger.write_pending(1, None, "0x" + "11" * 20, exclusive=True)
    with pytest.raises(FileExistsError):
        ledger.write_pending(1, None, "0x" + "11" * 20, exclusive=True)
    ledger.write_pending(1, "ab" * 32, "0x" + "11" * 20)  # updating is not creating
    assert loads_strict(ledger.pending_path(1).read_text())["tx"] == "ab" * 32


def test_a_marker_appearing_mid_flight_stops_the_second_anchor(ledger, sk, mac):
    """The window between the check and the write, closed."""
    b1 = ledger.append_from_request(make_request(ledger, sk, mac), sk,
                                    now=datetime(2026, 9, 3, tzinfo=MANILA))
    L = ledger

    class Racer:
        """Another run wins the race while this one is reading its nonce."""
        account = "0x" + "11" * 20
        contract = type("C", (), {"address": "0x" + "22" * 20})()
        sent = []
        class _Eth:
            chain_id = 8453
            def get_transaction_count(self, _):
                L.write_pending(1, None, "0x" + "33" * 20, exclusive=True)
                return 7
        w3 = type("W3", (), {"eth": _Eth()})()
        def anchor(self, block):
            Racer.sent.append(block.index)
            return "cd" * 32

    with pytest.raises((RuntimeError, FileExistsError)):
        L.anchor_with_marker(Racer(), b1)
    assert Racer.sent == [], "a second transaction went out"


def test_reconcile_refuses_an_unreadable_marker(ledger, sk, mac):
    """A marker is the only record that a transaction may be in flight. Truncated,
    it must stop the run loudly, never be stepped over."""
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    ledger.write_pending(1, "ab" * 32, "0x" + "11" * 20)
    p = ledger.pending_path(1)
    p.write_text(p.read_text()[: len(p.read_text()) // 2])  # killed mid-write
    with pytest.raises(RuntimeError) as e:
        ledger.reconcile(object())
    assert p.name in str(e.value)


def test_a_code_hash_pin_is_normalised_not_stripped(tmp_path):
    """`"0x" + digest.hex().lstrip("0x")` ate the leading zeros of one digest in
    sixteen and then compared it against a full one."""
    from aikiri_ledger.trust import REPO_DEFAULTS
    digest = "0a" + "cd" * 31
    for written in (digest, "0x" + digest, "0X" + digest.upper()):
        p = tmp_path / "t.json"
        p.write_text(json.dumps({"trust": dict(REPO_DEFAULTS, code_keccak=written)}))
        assert Trust.load(p).code_keccak == digest


def _parses(parser, argv) -> bool:
    try:
        parser.parse_args(argv)
        return True
    except SystemExit:
        return False


def test_every_documented_command_parses():
    """The four `verify --trust` invocations in this repo all put a global flag
    after the subcommand, so every one of them exits with a usage error ~ including
    the last step of the nightly and block workflows. Documentation that has never
    been run is a guess. This runs it."""
    import itertools
    import re
    import shlex
    from aikiri_ledger.cli import build_parser
    root = Path(__file__).parent.parent
    files = [*(root / ".github" / "workflows").glob("*.yml"),
             *(root / "docs").glob("*.md"), root / "README.md"]
    found = []
    for f in files:
        lines = f.read_text().splitlines()
        for lineno, line in enumerate(lines, 1):
            cmd = line.strip().removeprefix("run: ").removeprefix("$ ")
            if not cmd.startswith("aikiri-ledger "):
                continue
            while cmd.endswith("\\") and lineno < len(lines):  # a wrapped command
                cmd = cmd[:-1] + " " + lines[lineno].strip()
                lineno += 1
            cmd = cmd.split("#")[0]
            cmd = re.split(r"\||&&|;", cmd)[0].strip()  # drop shell plumbing
            found.append((f.relative_to(root), lineno, cmd))
    assert found, "no documented commands found; the scan is broken, not the docs"
    placeholder = re.compile(r"\$\{\{[^}]*\}\}|\$\{?\w+\}?|<[^>]*>")
    broken = []
    for path, lineno, cmd in found:
        try:
            tokens = shlex.split(cmd)[1:]
        except ValueError as e:
            broken.append(f"{path}:{lineno}: {cmd}  (unparseable shell: {e})")
            continue
        # A value filled in at run time is not what this checks. As a flag's value
        # it stands down to "1", valid as a string and as an int. Standing alone it
        # may expand to a positional, to a flag, or to nothing, and which is not
        # knowable here ~ so the command passes if any of those readings parses.
        choices = []
        for i, t in enumerate(tokens):
            if not placeholder.fullmatch(t):
                choices.append([t])
            elif i and tokens[i - 1].startswith("--"):
                choices.append(["1"])
            else:
                choices.append(["1", None])
        if not any(_parses(build_parser(), [t for t in argv if t is not None])
                   for argv in itertools.product(*choices)):
            broken.append(f"{path}:{lineno}: {cmd}")
    assert not broken, "commands that do not parse:\n  " + "\n  ".join(broken)


# ------------------------------------------- review findings, second pass ----

class _Honest:
    """A Base reader that agrees with the ledger about everything but the code."""
    address = "0x" + "11" * 20

    def __init__(self, code="ab" * 32, finalized=100):
        self._code, self._finalized = code, finalized

    def matches(self, b, block=None): return True
    def latest_index(self, block=None): return 1
    def genesis_hash(self): return None
    def owner(self): return None
    def record(self, i): return {"blockHash": None, "anchoredAt": 0, "by": None}
    def finalized_block(self): return self._finalized
    def code_hash(self, block=None): return self._code


def test_a_quorum_still_checks_the_deployed_code_pin(ledger, sk, mac, trust):
    """The pin was read through `base.w3`, which a QuorumBase does not have. So the
    multi-endpoint setup ~ the one that is actually recommended ~ skipped the check
    entirely and could still report BASE VERIFIED. More endpoints, fewer checks."""
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    trust.code_keccak = "ab" * 32
    q = QuorumBase([_Honest(), _Honest(), _Honest()])
    state, report = verify_all(ledger, trust, base=q)
    assert state != State.INVALID, report

    wrong = QuorumBase([_Honest(code="cd" * 32) for _ in range(3)])
    state, report = verify_all(ledger, trust, base=wrong)
    assert state == State.INVALID, report
    assert any("code" in r.lower() for r in report), report


def test_a_code_pin_that_cannot_be_read_is_not_a_pass(ledger, sk, mac, trust):
    """A pin nobody evaluated is not a pin that held."""
    ledger.append_from_request(make_request(ledger, sk, mac), sk,
                               now=datetime(2026, 9, 3, tzinfo=MANILA))
    trust.code_keccak = "ab" * 32

    class Mute(_Honest):
        code_hash = None  # offers no way to read the deployed code

    class Broken(_Honest):
        def code_hash(self, block=None): raise ConnectionError("node refused")

    for witness in (Mute(), Broken()):
        state, report = verify_all(ledger, trust, base=witness)
        assert state == State.INVALID, f"{type(witness).__name__}: {report}"


def test_finalized_block_zero_is_a_height_not_an_absence(ledger):
    """`if block_identifier` reads 0 as unset and silently falls back to the latest
    state, which is the one thing reading at a finalized height exists to avoid."""
    seen = []

    class Call:
        def call(self, **kw): seen.append(kw.get("block_identifier", "LATEST")); return 0

    class Contract:
        address = "0x" + "11" * 20
        class functions:
            @staticmethod
            def matches(*_): return Call()
            @staticmethod
            def latestIndex(): return Call()

    bw = BaseWitness.__new__(BaseWitness)
    bw.contract = Contract()
    bw.matches(ledger.read(0), block_identifier=0)
    bw.latest_index(block_identifier=0)
    assert seen == [0, 0], f"block 0 was dropped: {seen}"


# ------------------------------------------------ codex findings, PR #2 ----

def test_a_repo_trust_file_stays_repo_however_the_verifier_is_invoked(tmp_path, monkeypatch):
    """Containment was decided by walking up from the process's working directory.
    Run the verifier from anywhere else with absolute paths and the repo's own
    trust file was relabelled external ~ which lifts the VALID LOCALLY ceiling and
    lets a file the ledger's owner can rewrite certify the ledger as FULLY VERIFIED.
    Where the verifier happens to be standing is not a security property."""
    from aikiri_ledger.trust import REPO_DEFAULTS
    worktree = tmp_path / "repo"
    (worktree / ".git").mkdir(parents=True)
    (worktree / "ledger").mkdir()
    tf = worktree / "trust.json"
    tf.write_text(json.dumps({"trust": REPO_DEFAULTS}))

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    t = Trust.load(tf, ledger_root=worktree / "ledger")
    assert t.source == "repo", "a trust file beside the ledger it checks is not an anchor"
    assert not t.is_external


def test_a_trust_file_outside_the_ledgers_worktree_is_still_external(tmp_path, monkeypatch):
    """The ceiling must not go the other way either: a genuine anchor kept
    elsewhere stays external, including when the cwd happens to be the repo."""
    from aikiri_ledger.trust import REPO_DEFAULTS
    worktree = tmp_path / "repo"
    (worktree / ".git").mkdir(parents=True)
    (worktree / "ledger").mkdir()
    tf = tmp_path / "anchor" / "trust.json"
    tf.parent.mkdir()
    tf.write_text(json.dumps({"trust": REPO_DEFAULTS}))
    monkeypatch.chdir(worktree)
    assert Trust.load(tf, ledger_root=worktree / "ledger").source == "external-unsigned"


def test_the_block_workflow_supplies_the_enrolled_trust_file():
    """`aikiri-ledger block` reads the registered devices from the trust file. With
    no --trust it falls back to REPO_DEFAULTS, whose approval_keys list is empty, so
    the workflow exits "no approval devices registered" for every sealed request ~
    the one job this repository exists to run could never write a block."""
    import re
    import shlex
    from aikiri_ledger.cli import build_parser
    root = Path(__file__).parent.parent
    wf = (root / ".github" / "workflows" / "block.yml").read_text()
    env_trust = re.search(r"AIKIRI_TRUST\s*:", wf) is not None
    found = []
    for line in wf.splitlines():
        cmd = line.strip().removeprefix("run: ")
        if not cmd.startswith("aikiri-ledger "):
            continue
        cmd_only = re.split(r"\||&&|;", cmd)[0]
        # Only the subcommand and --trust matter here; stand run-time values down.
        argv = [re.sub(r"\$\{?\w+\}?", "1", t) for t in shlex.split(cmd_only)[1:]]
        a = build_parser().parse_args(argv)
        if a.cmd == "block":
            found.append((cmd, a.trust))
    assert found, "no block invocation found in block.yml"
    for cmd, trust in found:
        assert trust or env_trust, f"no trust file reaches: {cmd}"


def test_the_lock_carries_what_the_workflows_import():
    """The workflows install requirements.lock and then `pip install --no-deps -e .`,
    so anything in the lock is present and anything missing from it is not, whatever
    pyproject declares. py-solc-x is imported by compile_contract, which reconcile
    reaches on its first step."""
    import re
    root = Path(__file__).parent.parent
    pyproject = (root / "pyproject.toml").read_text()

    def norm(name): return re.sub(r"[-_.]+", "-", name.strip().lower())

    # Pinned requirement lines only. `# via py-solc-x` is a comment naming a
    # package's dependants, not the package being installed, and reading the whole
    # file as one string lets a comment stand in for the requirement.
    pinned = {norm(m.group(1)) for line in
              (root / "requirements.lock").read_text().splitlines()
              if (m := re.match(r"^([A-Za-z0-9_.-]+)==", line))}
    block = re.search(r"dependencies = \[(.*?)\]", pyproject, re.S).group(1)
    needed = [norm(d) for d in re.findall(r'"([A-Za-z0-9_.-]+)', block)]
    missing = [d for d in needed if d not in pinned]
    assert pinned, "no pinned requirements found; the scan is broken, not the lock"
    assert not missing, f"installed by no workflow: {missing}"


def test_nightly_proposes_proofs_instead_of_pushing_to_main():
    """nightly runs with no secrets and never could forge a block, but a
    standing `git push origin HEAD:main` is still a standing write credential
    for a job that only ever touches ledger/proofs. It must propose instead:
    open (or update) a pull request, never push to main itself."""
    import re
    text = (Path(".github/workflows") / "nightly.yml").read_text()
    # Not just the one spelling that used to be here: any shell push at main, in
    # whatever form a future edit writes it.
    assert not re.search(r"(?m)^\s*git\s+push\b.*(?:\bmain\b|refs/heads/main)", text), \
        "nightly must not push directly to main"
    assert "contents: write" in text, \
        "pushing the PR branch itself still needs contents: write"
    assert "pull-requests: write" in text, \
        "opening a PR needs pull-requests: write in permissions"
    assert "uses: peter-evans/create-pull-request@" in text, \
        "no pinned pull-request action found"
    assert "add-paths: ledger/proofs" in text, \
        "the PR must be scoped to ledger/proofs, not free to touch anything else"
    assert "branch: nightly/bitcoin-proofs" in text, \
        "reuse one branch across nights rather than opening a new PR each time"


# --------------------------------------------------- Bitcoin proof upkeep ----
class _FakeOts:
    """Stands in for `ots` in ledger/proofs, for the file effects these tests rely
    on (opentimestamps-client 0.7.2, otsclient/cmds.py):
    - stamp: creates <file>.ots, then writes the proof into it
    - upgrade: with something new, renames the proof to .bak (and refuses if one
      is there), creates the new file, writes the proof into it; with nothing
      new, "Failed! Timestamp not complete" (`pending`), or for a complete proof
      "Success! Timestamp complete", both leaving the file alone
    - stamp refuses a .ots that is already there
    - info: exit 1 if the file is not a proof ("Error! ... is not a timestamp
      file." for one that does not start like a proof, "Invalid timestamp file"
      for one that does and is cut short; real ots also says the first of a proof
      cut inside its header), else the digest it is of
    A fake proof is b"proof:<digest>:<label>" and carries its own digest, as a
    real one does; see _proof.
    `fail` names steps to make fail part-way, leaving what ots leaves then;
    `pending` is an upgrade with nothing new, `partial` one with something new
    that is still short of Bitcoin. It does not model a stamp that fails before
    it creates a file."""

    def __init__(self, fail=(), pending=False, partial=False):
        self.calls, self.fail, self.pending, self.partial = [], set(fail), pending, partial

    def __call__(self, argv, **kw):
        from types import SimpleNamespace
        ran = lambda rc: SimpleNamespace(returncode=rc, stdout="", stderr="")
        self.calls.append(list(argv))
        cmd, path = argv[1], Path(argv[-1])
        if cmd == "info":
            data = path.read_bytes() if path.exists() else b""
            parts = data.split(b":")
            if not data.startswith(b"proof:"):
                return SimpleNamespace(returncode=1, stdout="",
                                       stderr=f"Error! {str(path)!r} is not a timestamp file.\n")
            if len(parts) != 3:
                return SimpleNamespace(returncode=1, stdout="", stderr=(
                    f"Invalid timestamp file {str(path)!r}: Tried to read 32 bytes but got only 3 bytes\n"))
            return SimpleNamespace(returncode=0, stdout=f"File sha256 hash: {parts[1].decode()}\n"
                                   "Timestamp:\n", stderr="")
        if cmd == "stamp":
            out = Path(str(path) + ".ots")
            if os.path.lexists(out):  # opens the .ots with 'xb', which a dangling link refuses too
                raise subprocess.CalledProcessError(1, argv)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            out.write_bytes(_CUT if "stamp" in self.fail else f"proof:{digest}:pending".encode())
            if "stamp" in self.fail:
                raise subprocess.CalledProcessError(1, argv)
            return ran(0)
        if cmd == "upgrade":
            said = lambda rc, msg: SimpleNamespace(returncode=rc, stdout="", stderr=msg + "\n")
            bak = Path(str(path) + ".bak")
            old = path.read_bytes()
            if self.pending:  # nothing new from the calendars
                return said(1, "Failed! Timestamp not complete")
            if old.endswith(b":complete"):  # nothing new, and nothing to wait for
                return said(0, "Success! Timestamp complete")
            if bak.exists():
                return said(1, f"Could not backup timestamp: {str(bak)!r} already exists")
            path.rename(bak)
            if "upgrade" in self.fail:
                path.write_bytes(_CUT)
                return said(1, f"Could not upgrade timestamp {path}: [Errno 28] No space left on device")
            if self.partial:  # something new, still no Bitcoin attestation
                path.write_bytes(old.rsplit(b":", 1)[0] + b":more")
                return said(1, "Failed! Timestamp not complete")
            path.write_bytes(old.rsplit(b":", 1)[0] + b":complete")
            return said(0, "Success! Timestamp complete")
        return ran(0)


import os  # noqa: E402
import subprocess  # noqa: E402  (the fake raises what subprocess.run(check=True) raises)

_CUT = b"proof:cut"  # a proof whose write stopped part-way: it starts like one


def _proof(ledger, i, label, digest=None):
    """A fake proof of block i (or of `digest`), as _FakeOts writes and reads it."""
    digest = digest or hashlib.sha256(bytes.fromhex(ledger.read(i).hash)).hexdigest()
    return f"proof:{digest}:{label}".encode()


def _ots_paths(ledger, i):
    """The proof, its backup, and the .hash beside them, as stamp leaves it."""
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    ledger.proof_path(i, "hash").write_bytes(bytes.fromhex(ledger.read(i).hash))
    ots = ledger.proof_path(i, "hash.ots")
    return ots, Path(str(ots) + ".bak")


def test_upgrade_leaves_no_ots_backup_and_is_not_stopped_by_one(ledger, monkeypatch):
    from aikiri_ledger import witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    bak.write_bytes(_proof(ledger, 0, "older"))
    assert W.BitcoinWitness(ledger).upgrade(ledger.read(0)) == "upgraded, complete"
    assert ots.read_bytes() == _proof(ledger, 0, "complete") and not bak.exists()


def test_upgrade_that_fails_while_writing_keeps_the_good_proof(ledger, monkeypatch):
    # ots renames the proof to .bak, creates the new file, and can fail writing it
    # (a full disk), leaving a truncated proof beside the only good copy.
    from aikiri_ledger import witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts(fail={"upgrade"}))
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    with pytest.raises(W.OtsError, match="No space left"):
        W.BitcoinWitness(ledger).upgrade(ledger.read(0))
    assert ots.read_bytes() == _proof(ledger, 0, "pending") and not bak.exists()


@pytest.mark.parametrize("left", [None, b"", b"junk", _CUT])
@pytest.mark.parametrize("cmd", ["stamp", "upgrade"])
def test_a_backup_left_by_an_earlier_run_is_put_back_first(ledger, monkeypatch, left, cmd):
    # No proof, an empty one, junk, or a cut-short one beside a .bak: the .bak is the good
    # copy. `upgrade` puts it back rather than skip the block; `stamp` puts it back
    # rather than stamp over it.
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    ots, bak = _ots_paths(ledger, 0)
    bak.write_bytes(_proof(ledger, 0, "complete"))
    if left is not None:
        ots.write_bytes(left)
    assert cli.main(["--ledger", str(ledger.root), cmd]) == 0
    assert not any(c[1] == "stamp" for c in fake.calls)
    assert ots.read_bytes() == _proof(ledger, 0, "complete") and not bak.exists()


@pytest.mark.parametrize("left", [b"", b"junk", _CUT, "other block"])
def test_a_file_that_is_not_a_proof_of_the_block_is_named_not_stamped_over(ledger, monkeypatch, capsys, left):
    # An empty, junk, cut-short or foreign .ots with no .bak beside it is not a proof of the
    # block. It is reported, and left as it is: it may be the only trace of what
    # happened to the proof.
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, _ = _ots_paths(ledger, 0)
    if left == "other block":
        ots.write_bytes(_proof(ledger, 0, "pending", digest="00" * 32))
    else:
        ots.write_bytes(left)
    before = ots.read_bytes()
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    out = capsys.readouterr().out
    assert out.count("not a proof of this block") == 2
    assert not any(c[1] in ("stamp", "upgrade") for c in fake.calls)
    assert ots.read_bytes() == before


def test_a_proof_of_other_data_does_not_displace_the_backup(ledger, monkeypatch):
    # The .ots parses, but it is a proof of another digest: the .bak is the proof
    from aikiri_ledger import witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending", digest="00" * 32))
    bak.write_bytes(_proof(ledger, 0, "complete"))
    W.BitcoinWitness(ledger).settle_backup(ledger.read(0))
    assert ots.read_bytes() == _proof(ledger, 0, "complete") and not bak.exists()


@pytest.mark.parametrize("left", [None, b"junk"])
def test_a_backup_that_is_not_a_proof_is_not_put_back(ledger, monkeypatch, left):
    from aikiri_ledger import witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    ots, bak = _ots_paths(ledger, 0)
    bak.write_bytes(_proof(ledger, 0, "pending", digest="00" * 32))
    if left is not None:
        ots.write_bytes(left)
    W.BitcoinWitness(ledger).settle_backup(ledger.read(0))
    assert (ots.read_bytes() if ots.exists() else None) == left
    assert bak.exists()


@pytest.mark.parametrize("junk_ots", [False, True])
@pytest.mark.parametrize("cmd, rc", [("stamp", 1), ("witness", 0), ("upgrade", 0)])
def test_nothing_is_stamped_beside_a_backup_that_is_not_a_proof(ledger, monkeypatch, capsys, cmd, rc, junk_ots):
    # A .bak that is not a proof of the block, alone or beside an .ots that is not
    # one either. A new proof beside it would read as that backup's upgrade, and
    # the next settle would delete it. It is said once, in the command's own terms.
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, bak = _ots_paths(ledger, 0)
    bak.write_bytes(b"junk")
    if junk_ots:
        ots.write_bytes(b"other junk")
    argv = [cmd] + (["0"] if cmd == "witness" else [])
    assert cli.main(["--ledger", str(ledger.root), *argv]) == rc
    assert not any(c[1] in ("stamp", "upgrade") for c in fake.calls)
    assert (ots.read_bytes() if ots.exists() else None) == (b"other junk" if junk_ots else None)
    assert bak.read_bytes() == b"junk"
    out = capsys.readouterr().out
    assert out.count("not a proof of this block") == 1
    assert ".ots.bak there is not a proof of this block" in out
    assert ("nothing upgraded" if cmd == "upgrade" else "nothing stamped") in out


def test_ots_backups_are_never_committed():
    r = subprocess.run(["git", "check-ignore", "-q", "ledger/proofs/000001.hash.ots.bak"])
    assert r.returncode == 0, "nightly adds ledger/proofs; a .bak must not ride along"


def _three_blocks(ledger, sk, mac):
    for day, nonce in ((3, "cc" * 32), (4, "dd" * 32)):
        ledger.append_from_request(make_request(ledger, sk, mac, nonce=nonce), sk,
                                   now=datetime(2026, 9, day, tzinfo=MANILA))


def test_stamp_stamps_every_block_without_a_proof_and_only_those(ledger, sk, mac, monkeypatch):
    from aikiri_ledger import cli, witness as W
    _three_blocks(ledger, sk, mac)
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    _ots_paths(ledger, 1)[0].write_bytes(_proof(ledger, 1, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 0
    stamped = sorted(c[-1] for c in fake.calls if c[1] == "stamp")
    assert stamped == [str(ledger.proof_path(0, "hash")), str(ledger.proof_path(2, "hash"))]
    assert ledger.proof_path(0, "hash").read_bytes() == bytes.fromhex(ledger.read(0).hash)
    assert ledger.proof_path(1, "hash.ots").read_bytes() == _proof(ledger, 1, "pending")
    n = len(fake.calls)
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 0
    assert not any(c[1] == "stamp" for c in fake.calls[n:]), "a block with a proof is not stamped again"


def test_a_failed_stamp_leaves_nothing_and_the_rest_are_still_stamped(ledger, sk, mac, monkeypatch):
    # ots stamp creates the .ots before writing it. A cut-short one left behind
    # would be reported as not a proof and the block never stamped again; a lone
    # .hash would ride into nightly's PR on its own.
    from aikiri_ledger import cli, witness as W
    _three_blocks(ledger, sk, mac)
    real = _FakeOts()
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        if argv[1] == "stamp" and argv[-1].endswith("000000.hash"):
            return _FakeOts(fail={"stamp"})(argv, **kw)
        return real(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert not ledger.proof_path(0, "hash.ots").exists()
    assert not ledger.proof_path(0, "hash").exists()
    assert ledger.proof_path(1, "hash.ots").exists() and ledger.proof_path(2, "hash.ots").exists()


def test_witness_goes_on_when_the_bitcoin_stamp_fails(ledger, monkeypatch, capsys):
    # block.yml commits the block only after `witness`. If the stamp failed after
    # the Base anchor, the anchored block was never committed, and a rerun writes a
    # different block N that Base refuses (AlreadyAnchored). Nightly stamps any
    # block with no .ots, so a failed stamp can wait for it.
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts(fail={"stamp"}))
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    assert cli.main(["--ledger", str(ledger.root), "witness", "0"]) == 0
    assert "nightly" in capsys.readouterr().out
    assert not ledger.proof_path(0, "hash.ots").exists()


@pytest.mark.parametrize("before, says", [
    ("proof", "block 0 already has a proof"),
    ("backup only", "block 0 already has a proof"),
    ("not a proof", "not a proof of this block"),
])
def test_witness_settles_first_and_keeps_what_it_finds(ledger, monkeypatch, capsys, before, says):
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, bak = _ots_paths(ledger, 0)
    content = b"junk" if before == "not a proof" else _proof(ledger, 0, "complete")
    (bak if before == "backup only" else ots).write_bytes(content)
    assert cli.main(["--ledger", str(ledger.root), "witness", "0"]) == 0
    assert not any(c[1] == "stamp" for c in fake.calls)
    assert ots.read_bytes() == content and not bak.exists()
    out = capsys.readouterr().out
    assert says in out and "nightly" not in out


def test_a_failed_stamp_never_removes_a_proof_that_was_there(ledger, monkeypatch):
    # BitcoinWitness.stamp cleans up only what a failed ots stamp made
    from aikiri_ledger import witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    ots, _ = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "complete"))
    with pytest.raises(subprocess.CalledProcessError):
        W.BitcoinWitness(ledger).stamp(ledger.read(0))
    assert ots.read_bytes() == _proof(ledger, 0, "complete")
    assert ledger.proof_path(0, "hash").exists()


@pytest.mark.parametrize("was_there", [False, True])
def test_a_stamp_that_cannot_write_the_digest_changes_nothing(ledger, monkeypatch, was_there):
    # A full disk while writing <index>.hash: a new one leaves nothing, and one that
    # was there is not cut short (nightly's PR adds ledger/proofs as it finds it)
    from aikiri_ledger import witness as W
    digest = ledger.proof_path(0, "hash")
    if was_there:
        ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
        digest.write_bytes(bytes.fromhex(ledger.read(0).hash))
    def full(fd, data):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(W.os, "write", full)
    with pytest.raises(OSError):
        W.BitcoinWitness(ledger).stamp(ledger.read(0))
    if was_there:
        assert digest.read_bytes() == bytes.fromhex(ledger.read(0).hash)
    else:
        assert not digest.exists()
    assert [p.name for p in ledger.proofs_dir.iterdir()] == (["000000.hash"] if was_there else [])


@pytest.mark.parametrize("stop", [KeyboardInterrupt, SystemExit])
def test_a_stamp_interrupted_leaves_nothing(ledger, monkeypatch, stop):
    # Ctrl-C, or an exit, while ots stamp runs: the cleanup runs all the same
    from aikiri_ledger import witness as W
    def interrupted(argv, **kw):
        raise stop()
    monkeypatch.setattr(W.subprocess, "run", interrupted)
    with pytest.raises(stop):
        W.BitcoinWitness(ledger).stamp(ledger.read(0))
    assert not ledger.proof_path(0, "hash").exists()


def test_nightly_stamps_blocks_without_a_proof_before_proposing():
    text = (Path(".github/workflows") / "nightly.yml").read_text()
    assert "aikiri-ledger stamp" in text
    assert text.index("aikiri-ledger stamp") < text.index("uses: peter-evans/create-pull-request@")


def test_block_commit_says_whether_there_is_a_bitcoin_proof():
    # witness goes on when the stamp fails or finds a file that is not a proof, and
    # main's history is never rewritten: the commit's OTS line comes from what is
    # on disk, checked as a proof of the block, not from whether a file exists.
    text = (Path(".github/workflows") / "block.yml").read_text()
    step = text[text.index("- name: commit the block and its proofs"):text.index("- name: verify")]
    assert 'OTS=$(aikiri-ledger proof-status "$INDEX") || OTS="unknown; proof-status failed"' in step
    assert "test -f" not in step and "OTS       $OTS" in step


_NONE = "none; not stamped, nightly stamps it"
_NEVER = " (the .ots.bak here is never committed; nightly works from main)"
_NEITHER = "none; the file there is not a proof of this block"


@pytest.mark.parametrize("on_disk, backup, says", [
    ("proof", None, "stamped; a proof of this block"),
    ("proof", "junk", "stamped; a proof of this block"),
    ("proof", "proof", "stamped; a proof of this block"),
    ("junk", None, _NEITHER),
    (None, None, _NONE),
    (None, "proof", _NONE + _NEVER),
    (_CUT, "proof", _NEITHER),
    (None, "junk", _NONE + _NEVER),
    ("junk", "junk", _NEITHER),
    (None, "dangling", _NONE + _NEVER),
])
def test_proof_status_says_what_is_there(ledger, monkeypatch, capsys, on_disk, backup, says):
    # The .ots alone, as a commit carries it; a .bak is never committed. It changes
    # no file.
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, bak = _ots_paths(ledger, 0)
    for path, what in ((ots, on_disk), (bak, backup)):
        if what == "dangling":
            path.symlink_to("nowhere")
        elif what is not None:
            path.write_bytes(_proof(ledger, 0, "pending") if what == "proof"
                             else b"junk" if what == "junk" else what)
    state = lambda: [(os.path.lexists(p), p.is_symlink(), p.read_bytes() if p.exists() else None)
                     for p in (ots, bak)]
    before = state()
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "0"]) == 0
    assert capsys.readouterr().out.strip() == says
    assert state() == before



def test_proof_status_never_fails_the_commit_step(ledger, monkeypatch, capsys):
    # It runs after the Base anchor, which cannot be taken back
    from aikiri_ledger import cli, witness as W
    def broken(*a, **k):
        raise OSError("ots could not run")
    monkeypatch.setattr(W.subprocess, "run", broken)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    _ots_paths(ledger, 0)[0].write_bytes(b"anything")
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "0"]) == 0
    assert capsys.readouterr().out.startswith("unknown; ")


def _ots_crashes(argv, **kw):
    """ots failing before it reads the file (a broken install or cache)."""
    from types import SimpleNamespace
    _ots_crashes.calls.append(list(argv))
    if kw.get("check"):
        raise subprocess.CalledProcessError(1, argv)
    return SimpleNamespace(returncode=1, stdout="", stderr=(
        "Traceback (most recent call last):\n"
        "FileNotFoundError: [Errno 2] No such file or directory: '/proc/nopé'\x1b]8;;x\x07\n"))


def test_ots_failing_to_run_is_not_read_as_not_a_proof(ledger, monkeypatch, capsys):
    # "not a proof" is what ots says of a file it read; ots not running says nothing
    # about the file. Nothing is stamped over, put back or deleted on it.
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    bak.write_bytes(_proof(ledger, 0, "older"))
    monkeypatch.setattr(W.subprocess, "run", _ots_crashes)
    monkeypatch.setattr(_ots_crashes, "calls", [], raising=False)
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "0"]) == 0
    status = capsys.readouterr().out
    assert status.startswith("unknown; ") and status.count("\n") == 1, "one line, for the commit"
    assert status.isascii() and status[:-1].isprintable(), "ots's own text is cleaned for the commit"
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert cli.main(["--ledger", str(ledger.root), "witness", "0"]) == 0
    out = capsys.readouterr().out
    assert "not a proof" not in out and "could not" in out
    assert out.isascii() and all(l.isprintable() for l in out.splitlines()), "ots's words, cleaned"
    assert ots.read_bytes() == _proof(ledger, 0, "pending")
    assert bak.read_bytes() == _proof(ledger, 0, "older")
    assert not any(c[1] == "stamp" for c in _ots_crashes.calls)


@pytest.mark.parametrize("cmd, rc", [("stamp", 1), ("witness", 0)])
def test_ots_failing_to_run_stamps_nothing_beside_a_lone_backup(ledger, monkeypatch, cmd, rc):
    # Only a .bak, and ots cannot say what it is: nothing is stamped beside it
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    monkeypatch.setattr(W.subprocess, "run", _ots_crashes)
    monkeypatch.setattr(_ots_crashes, "calls", [], raising=False)
    ots, bak = _ots_paths(ledger, 0)
    bak.write_bytes(_proof(ledger, 0, "older"))
    argv = [cmd] + (["0"] if cmd == "witness" else [])
    assert cli.main(["--ledger", str(ledger.root), *argv]) == rc
    assert not any(c[1] == "stamp" for c in _ots_crashes.calls)
    assert not ots.exists() and bak.read_bytes() == _proof(ledger, 0, "older")


def test_proof_status_of_a_block_that_cannot_be_read_is_unknown(ledger, capsys):
    from aikiri_ledger import cli
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "7"]) == 0
    assert capsys.readouterr().out.startswith("unknown; ")


@pytest.mark.parametrize("says", ["none; not stamped, nightly stamps it",
                                  "stamped; a proof of this block",
                                  None])
def test_block_commit_step_runs_and_writes_the_ots_line(tmp_path, says):
    # The commit step itself, under bash -e, with git and aikiri-ledger stood in.
    # proof-status never fails; if it dies anyway (None), the commit still happens.
    import os
    import stat
    import textwrap
    lines = (Path(".github/workflows") / "block.yml").read_text().splitlines()
    at = next(i for i, l in enumerate(lines) if l.strip() == "- name: commit the block and its proofs")
    run = next(i for i in range(at, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[run]) - len(lines[run].lstrip())
    body = []
    for l in lines[run + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) <= indent:
            break
        body.append(l)
    script = textwrap.dedent("\n".join(body))
    (tmp_path / "ledger/blocks").mkdir(parents=True)
    (tmp_path / "ledger/proofs").mkdir()
    (tmp_path / "ledger/blocks/000003.json").write_text(json.dumps({
        "hash": "ab" * 32, "roots": [{"kind": "journal", "sha256": "cd" * 32}],
        "approval": {"device": "mac"}}))
    (tmp_path / "ledger/proofs/000003.base.json").write_text(json.dumps({"tx": "0xfeed"}))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, body in (("git", 'if [ "$1" = commit ]; then cat > "$MSGFILE"; fi\n'),
                       ("aikiri-ledger", f'echo "{says}"\n' if says
                                         else 'echo "stamped; a proof of this block"\nexit 139\n')):
        exe = bin_ / name
        exe.write_text("#!/bin/sh\n" + body)
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "INDEX": "3",
           "MSGFILE": str(tmp_path / "msg")}
    subprocess.run(["bash", "-e", "-c", script], cwd=tmp_path, env=env, check=True)
    msg = (tmp_path / "msg").read_text()
    assert f"OTS       {says or 'unknown; proof-status failed'}\n" in msg and "Base      tx 0xfeed" in msg
    if not says:  # what it printed before it died is not kept beside the fallback
        assert "stamped" not in msg


def test_an_upgrade_whose_output_cannot_be_checked_keeps_the_proof(ledger, monkeypatch, capsys):
    # ots renames the proof to .bak and fails writing the new one; then ots cannot
    # run to say what it left. The .bak is the proof checked just before: it goes
    # back, rather than leave a cut-short file to be proposed in its place.
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts(fail={"upgrade"})
    def run(argv, **kw):
        if argv[1] == "info" and any(c[1] == "upgrade" for c in fake.calls):
            return _ots_crashes(argv, **kw)
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    monkeypatch.setattr(_ots_crashes, "calls", [], raising=False)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert "could not check" in capsys.readouterr().out
    assert ots.read_bytes() == _proof(ledger, 0, "pending") and not bak.exists()


@pytest.mark.parametrize("cmd, rc", [("witness", 0), ("upgrade", 0), ("stamp", 1)])
def test_an_ots_that_cannot_be_executed_is_ots_not_running(ledger, monkeypatch, capsys, cmd, rc):
    # A broken shebang: subprocess.run raises rather than return an exit code
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    def run(argv, **kw):
        raise FileNotFoundError(2, "No such file or directory", "ots")
    monkeypatch.setattr(W.subprocess, "run", run)
    ots, _ = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    argv = [cmd] + (["0"] if cmd == "witness" else [])
    assert cli.main(["--ledger", str(ledger.root), *argv]) == rc
    assert "could not check" in capsys.readouterr().out
    assert ots.read_bytes() == _proof(ledger, 0, "pending")


def test_upgrade_touches_nothing_beside_a_backup_that_is_not_a_proof(ledger, monkeypatch):
    # Neither file is a proof: ots is not asked to upgrade, and if it cannot run
    # afterwards nothing is put back over anything
    from aikiri_ledger import witness as W
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == "info" and any(c[1] == "upgrade" for c in fake.calls):
            return _ots_crashes(argv, **kw)
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    monkeypatch.setattr(_ots_crashes, "calls", [], raising=False)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(b"junk")
    bak.write_bytes(b"other junk")
    assert W.BitcoinWitness(ledger).upgrade(ledger.read(0)) == "blocked"
    assert not any(c[1] == "upgrade" for c in fake.calls)
    assert ots.read_bytes() == b"junk" and bak.read_bytes() == b"other junk"


def test_an_ots_upgrade_that_cannot_be_executed_is_ots_not_running(ledger, monkeypatch, capsys):
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == "upgrade":
            raise PermissionError(13, "Permission denied", "ots")
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert "could not check" in capsys.readouterr().out
    assert ots.read_bytes() == _proof(ledger, 0, "pending") and not bak.exists()


@pytest.mark.parametrize("cmd, rc", [("witness", 0), ("upgrade", 0), ("stamp", 1)])
def test_ots_output_that_is_not_utf8_is_ots_not_running(ledger, monkeypatch, tmp_path, capsys, cmd, rc):
    # A real executable on PATH, since only a real pipe carries undecodable bytes
    import os
    import stat
    from aikiri_ledger import cli
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    ots_exe = bin_ / "ots"
    ots_exe.write_text("#!/bin/sh\nprintf 'Traceback\\n\\377\\376\\n' >&2\nexit 1\n")
    ots_exe.chmod(ots_exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_}{os.pathsep}{os.environ['PATH']}")
    ots, _ = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    argv = [cmd] + (["0"] if cmd == "witness" else [])
    assert cli.main(["--ledger", str(ledger.root), *argv]) == rc
    assert "could not check" in capsys.readouterr().out
    assert ots.read_bytes() == _proof(ledger, 0, "pending")


def test_an_ots_upgrade_that_prints_bytes_not_utf8_is_still_pending(ledger, monkeypatch, tmp_path, capsys):
    import os
    import stat
    from aikiri_ledger import cli
    digest = hashlib.sha256(bytes.fromhex(ledger.read(0).hash)).hexdigest()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    ots_exe = bin_ / "ots"
    ots_exe.write_text("#!/bin/sh\n"
                       f"[ \"$1\" = info ] && {{ echo 'File sha256 hash: {digest}'; exit 0; }}\n"
                       "printf 'Failed! Timestamp not complete\\n\\377\\376\\n' >&2\nexit 1\n")
    ots_exe.chmod(ots_exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_}{os.pathsep}{os.environ['PATH']}")
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert "block 0: still pending" in capsys.readouterr().out
    assert ots.read_bytes() == _proof(ledger, 0, "pending") and not bak.exists()


def test_proof_status_with_nothing_there_is_none_even_without_ots(ledger, monkeypatch, capsys):
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: False))
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "0"]) == 0
    assert capsys.readouterr().out == "none; not stamped, nightly stamps it\n"


@pytest.mark.parametrize("cmd, rc", [("witness", 0), ("upgrade", 0), ("stamp", 1)])
def test_a_proofs_folder_that_cannot_be_written_stops_nothing(ledger, monkeypatch, capsys, cmd, rc):
    # Putting a .bak back can fail (a read-only folder). The command says so and
    # goes on: witness still exits 0 after the Base anchor.
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    def refused(*a, **k):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(W.os, "replace", refused)
    _, bak = _ots_paths(ledger, 0)
    bak.write_bytes(_proof(ledger, 0, "pending"))
    argv = [cmd] + (["0"] if cmd == "witness" else [])
    assert cli.main(["--ledger", str(ledger.root), *argv]) == rc
    assert "Permission denied" in capsys.readouterr().out
    assert bak.read_bytes() == _proof(ledger, 0, "pending")


def test_an_ots_upgrade_that_crashed_is_not_still_pending(ledger, monkeypatch, capsys):
    # A traceback is ots not running, not a proof that is not complete yet
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == "upgrade":
            fake.calls.append(list(argv))
            return _ots_crashes(argv, **kw)
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    monkeypatch.setattr(_ots_crashes, "calls", [], raising=False)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    out = capsys.readouterr().out
    assert "still pending" not in out and "ots upgrade failed" in out
    assert ots.read_bytes() == _proof(ledger, 0, "pending") and not bak.exists()


def test_a_failed_stamp_leaves_a_dangling_link_where_it_was(ledger, monkeypatch, tmp_path):
    # A link to nothing is not "no .ots": the cleanup removes only what ots made
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, _ = _ots_paths(ledger, 0)
    ots.symlink_to(tmp_path / "nowhere")
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert ots.is_symlink() and not (tmp_path / "nowhere").exists()


@pytest.mark.parametrize("on_disk, fake, says", [
    ("pending", dict(pending=True), "block 0: still pending"),
    ("complete", {}, "block 0: already complete"),
    ("pending", {}, "block 0: upgraded, complete\n"),
    ("pending", dict(partial=True), "block 0: upgraded, still pending"),
])
def test_upgrade_says_what_ots_said(ledger, monkeypatch, capsys, on_disk, fake, says):
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts(**fake))
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, on_disk))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert says in capsys.readouterr().out
    assert not bak.exists()


def test_an_upgrade_ots_could_not_write_is_not_still_pending(ledger, monkeypatch, capsys):
    # ots had the upgrade and could not rename the proof to .bak: an error, not
    # a proof that is not complete yet (otsclient/cmds.py upgrade_command)
    from aikiri_ledger import cli, witness as W
    from types import SimpleNamespace
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == "upgrade":
            return SimpleNamespace(returncode=1, stdout="", stderr=(
                "Got 1 attestation(s) from cache\n"
                "Could not backup timestamp: [Errno 1] Operation not permitted\n"))
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    out = capsys.readouterr().out
    assert "still pending" not in out and "Operation not permitted" in out
    assert ots.read_bytes() == _proof(ledger, 0, "pending") and not bak.exists()


def test_a_failed_stamp_removes_the_hash_it_wrote_over_a_dangling_link(ledger, monkeypatch, tmp_path):
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts(fail={"stamp"}))
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    digest = ledger.proof_path(0, "hash")
    digest.symlink_to(tmp_path / "nowhere")
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert not os.path.lexists(digest) and not ledger.proof_path(0, "hash.ots").exists()


def test_a_dangling_link_at_the_ots_is_a_file_that_is_not_a_proof(ledger, monkeypatch, capsys, tmp_path):
    # Not "none; not stamped": no stamp can ever write there, so it is named
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, _ = _ots_paths(ledger, 0)
    ots.symlink_to(tmp_path / "nowhere")
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "0"]) == 0
    assert capsys.readouterr().out == "none; the file there is not a proof of this block\n"
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert cli.main(["--ledger", str(ledger.root), "witness", "0"]) == 0
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert capsys.readouterr().out.count("not a proof of this block") == 3
    assert not any(c[1] == "stamp" for c in fake.calls) and ots.is_symlink()


@pytest.mark.parametrize("rc, stderr", [
    (1, "Traceback (most recent call last):\nBrokenPipeError: [Errno 32] Broken pipe\n"),
    (-9, ""),
])
def test_an_upgrade_on_disk_is_upgraded_however_ots_exited(ledger, monkeypatch, capsys, rc, stderr):
    # What is on disk decides: ots wrote the upgrade, then died on its way out
    from aikiri_ledger import cli, witness as W
    from types import SimpleNamespace
    fake = _FakeOts()
    def run(argv, **kw):
        r = fake(argv, **kw)
        return SimpleNamespace(returncode=rc, stdout="", stderr=stderr) if argv[1] == "upgrade" else r
    monkeypatch.setattr(W.subprocess, "run", run)
    ots, bak = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    # Kept, and not called complete: only an exit 0 says that
    assert f"block 0: upgraded, not called complete: ots exited {rc}" \
        in capsys.readouterr().out
    assert ots.read_bytes() == _proof(ledger, 0, "complete") and not bak.exists()


def test_an_ots_upgrade_killed_with_nothing_on_disk_is_not_still_pending(ledger, monkeypatch, capsys):
    from aikiri_ledger import cli, witness as W
    from types import SimpleNamespace
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == "upgrade":
            return SimpleNamespace(returncode=-9, stdout="", stderr="")
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    ots, _ = _ots_paths(ledger, 0)
    ots.write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    out = capsys.readouterr().out
    assert "still pending" not in out and "exit -9" in out
    assert "ots upgrade failed, exit -9" in out


def test_the_hash_is_never_written_through_a_link(ledger, monkeypatch, tmp_path):
    # A link at .hash.tmp is removed, never followed, and the stamp goes on
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    elsewhere = tmp_path / "elsewhere.ots"
    elsewhere.write_bytes(b"someone's proof")
    ledger.proof_path(0, "hash.tmp").symlink_to(elsewhere)
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 0
    assert elsewhere.read_bytes() == b"someone's proof"
    assert not os.path.lexists(ledger.proof_path(0, "hash.tmp"))


def test_a_link_is_never_a_proof(ledger, monkeypatch, capsys):
    # An .ots that links to its own .bak: the proof in the .bak goes back as a file
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, bak = _ots_paths(ledger, 0)
    bak.write_bytes(_proof(ledger, 0, "pending"))
    ots.symlink_to(bak.name)
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "0"]) == 0
    assert capsys.readouterr().out == _NEITHER + "\n"
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert not ots.is_symlink() and not bak.exists()
    assert ots.read_bytes() == _proof(ledger, 0, "complete")


@pytest.mark.parametrize("cmd", ["upgrade", "stamp"])
def test_one_blocks_error_does_not_stop_the_others(ledger, sk, mac, monkeypatch, capsys, cmd):
    from aikiri_ledger import cli, witness as W
    _three_blocks(ledger, sk, mac)
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    real = W.os.replace
    def refused(src, dst, *a, **k):
        if str(src).endswith("000000.hash.ots.bak"):
            raise PermissionError(13, "Permission denied")
        return real(src, dst, *a, **k)
    monkeypatch.setattr(W.os, "replace", refused)
    _, bak = _ots_paths(ledger, 0)
    bak.write_bytes(_proof(ledger, 0, "pending"))
    if cmd == "upgrade":  # stamp says nothing of a block that has a proof
        for i in (1, 2):
            _ots_paths(ledger, i)[0].write_bytes(_proof(ledger, i, "pending"))
    cli.main(["--ledger", str(ledger.root), cmd])
    out = capsys.readouterr().out
    assert "block 0: " in out and "Permission denied" in out
    assert "block 1: " in out and "block 2: " in out


def test_what_ots_says_reaches_the_log_as_one_plain_line(ledger, monkeypatch, capsys):
    from aikiri_ledger import cli, witness as W
    from types import SimpleNamespace
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == "upgrade":
            return SimpleNamespace(returncode=1, stdout="", stderr="Could not \x1b[2Jupgrade: é\x07\n")
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    _ots_paths(ledger, 0)[0].write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    out = capsys.readouterr().out
    assert out.isascii() and out.count("\n") == 1 and out[:-1].isprintable()


def test_upgrade_of_what_is_not_a_proof_does_nothing(ledger, monkeypatch, tmp_path):
    # The CLI checks first; called directly, upgrade() checks too
    from aikiri_ledger import witness as W
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    bw, blk = W.BitcoinWitness(ledger), ledger.read(0)
    ots, _ = _ots_paths(ledger, 0)
    assert bw.upgrade(blk) == "no proof"
    real = tmp_path / "elsewhere.ots"
    real.write_bytes(_proof(ledger, 0, "pending"))
    ots.symlink_to(real)
    assert bw.upgrade(blk) == "no proof"
    assert not any(c[1] == "upgrade" for c in fake.calls)
    assert real.read_bytes() == _proof(ledger, 0, "pending")


def test_a_failed_stamps_cleanup_never_removes_a_link(ledger, monkeypatch, tmp_path):
    # The cleanup removes only files this run made, and it makes no links: one at
    # .hash that the stamp never got to replace is left
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts())
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"theirs")
    digest = ledger.proof_path(0, "hash")
    digest.symlink_to(victim)
    ledger.proof_path(0, "hash.tmp").mkdir()
    (ledger.proof_path(0, "hash.tmp") / "x").write_bytes(b"")  # the temp write fails
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert digest.is_symlink() and victim.read_bytes() == b"theirs"


def test_a_failed_stamp_leaves_no_hash_it_wrote_over_a_live_link(ledger, monkeypatch, tmp_path):
    # _digest_file replaces the link with this run's own file; that file goes
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.subprocess, "run", _FakeOts(fail={"stamp"}))
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"theirs")
    ledger.proof_path(0, "hash").symlink_to(victim)
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert not os.path.lexists(ledger.proof_path(0, "hash")) and victim.read_bytes() == b"theirs"


def test_only_ots_own_line_is_pending(ledger, monkeypatch, capsys):
    # The words inside another line are not ots saying the proof is incomplete
    from aikiri_ledger import cli, witness as W
    from types import SimpleNamespace
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == "upgrade":
            return SimpleNamespace(returncode=1, stdout="",
                                   stderr="Calendar x: Failed! Timestamp not complete, and more\n")
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    _ots_paths(ledger, 0)[0].write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert "still pending" not in capsys.readouterr().out


def test_a_dangling_backup_link_blocks_a_stamp_like_any_bad_backup(ledger, monkeypatch, capsys):
    from aikiri_ledger import cli, witness as W
    fake = _FakeOts()
    monkeypatch.setattr(W.subprocess, "run", fake)
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    ots, bak = _ots_paths(ledger, 0)
    bak.symlink_to("nowhere")
    assert cli.main(["--ledger", str(ledger.root), "stamp"]) == 1
    assert ".ots.bak there is not a proof of this block" in capsys.readouterr().out
    assert not any(c[1] == "stamp" for c in fake.calls)
    assert bak.is_symlink() and not os.path.lexists(ots)


def test_an_ots_info_that_did_not_run_gives_its_exit_code(ledger, monkeypatch, capsys):
    from aikiri_ledger import cli, witness as W
    monkeypatch.setattr(W.BitcoinWitness, "available", staticmethod(lambda: True))
    monkeypatch.setattr(W.subprocess, "run", _ots_crashes)
    monkeypatch.setattr(_ots_crashes, "calls", [], raising=False)
    _ots_paths(ledger, 0)[0].write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "proof-status", "0"]) == 0
    assert "ots info did not run, exit 1: " in capsys.readouterr().out


@pytest.mark.parametrize("cmd", ["upgrade", "info"])
def test_an_ots_killed_after_speaking_still_gives_its_exit_code(ledger, monkeypatch, capsys, cmd):
    from aikiri_ledger import cli, witness as W
    from types import SimpleNamespace
    fake = _FakeOts()
    def run(argv, **kw):
        if argv[1] == cmd:
            return SimpleNamespace(returncode=-9, stdout="", stderr="Checking calendar\n")
        return fake(argv, **kw)
    monkeypatch.setattr(W.subprocess, "run", run)
    _ots_paths(ledger, 0)[0].write_bytes(_proof(ledger, 0, "pending"))
    assert cli.main(["--ledger", str(ledger.root), "upgrade"]) == 0
    assert f"ots {cmd} " in (out := capsys.readouterr().out) and "exit -9: Checking calendar" in out
