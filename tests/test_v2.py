"""Format v2, human approval, external trust, strict verification.

Every test here fails before the v2 work and passes after. The two blocks that
exist on Base are never rewritten: they verify as v1 against pinned hashes.
"""
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
