"""The original suite, carried onto format v2.

Nine of the first eleven tests still assert what they always did. Three could
not survive unchanged, because what they asserted is what v2 removes:
`test_seal_and_block` and `test_refuses_empty_block` tested the queue, which no
longer exists, and `test_wrong_key_rejected` asserted that any consistent signer
is accepted, which was the bug. They are rewritten below under names that say
what they now check.
"""
import json
from datetime import datetime
from pathlib import Path

import pytest
from web3 import Web3, EthereumTesterProvider

from aikiri_ledger.approval import ApprovalKey, SoftwareApprover
from aikiri_ledger.chain import Ledger, Block, new_key, save_key, load_key, sha256_file, merkle_root, MANILA
from aikiri_ledger.errors import SchemaError
from aikiri_ledger.request import Request
from aikiri_ledger.trust import Trust
from aikiri_ledger.verify import State, verify_chain, verify_all
from aikiri_ledger.witness import compile_contract, BaseWitness


@pytest.fixture
def key(tmp_path):
    sk = new_key()
    save_key(sk, tmp_path / "keys" / "chii.key")
    return load_key(tmp_path / "keys" / "chii.key")


@pytest.fixture
def mac():
    return SoftwareApprover.from_seed(b"\x01" * 32, "mac")


@pytest.fixture
def ledger(tmp_path, key):
    L = Ledger(tmp_path / "ledger")
    L.init(key, now=datetime(2026, 9, 2, 2, 32, tzinfo=MANILA))
    return L


@pytest.fixture
def trust(ledger, key, mac):
    return Trust(chain_id=8453, contract=None, owner=None, code_keccak=None,
                 genesis_hash=ledger.read(0).hash, validator=key.verify_key.encode().hex(),
                 approval_keys=[ApprovalKey("mac", mac.public_key_hex)],
                 legacy={0: ledger.read(0).hash}, source="external")


@pytest.fixture
def journal(tmp_path):
    p = tmp_path / "decision-journal.md"
    p.write_text("## 2026-09-02\n- I am deciding to dive deeper into the Aikiri Network's "
                 "very reason for existing.\n")
    return p


def approved(ledger, key, approver, sha, kind="journal", nonce="cc" * 32):
    head = ledger.head()
    return Request.build(index=head.index + 1, prev_hash=head.hash,
                         roots=[{"kind": kind, "sha256": sha}], nonce=nonce,
                         validator=key.verify_key.encode().hex(), approver=approver)


def add(ledger, key, approver, sha, kind="journal", nonce="cc" * 32, now=None):
    return ledger.append_from_request(approved(ledger, key, approver, sha, kind, nonce), key,
                                      now=now or datetime(2026, 9, 3, tzinfo=MANILA),
                                      registered=[approver.as_key()])


def test_genesis_and_verify(ledger, trust):
    state, report = verify_chain(ledger, trust)
    assert state == State.VALID_LOCALLY, report
    g = ledger.read(0)
    assert g.index == 0 and g.roots == [] and len(g.hash) == 64


def test_approved_request_becomes_a_block(ledger, key, mac, journal, trust):
    """Replaces test_seal_and_block: the queue is gone, a sealed request takes its place."""
    b = add(ledger, key, mac, sha256_file(journal))
    assert b.index == 1 and b.prev_hash == ledger.read(0).hash
    assert b.roots == [{"kind": "journal", "sha256": sha256_file(journal)}]
    assert b.approval["device"] == "mac"
    state, report = verify_chain(ledger, trust)
    assert state == State.VALID_LOCALLY, report


def test_a_block_needs_a_request(ledger, key):
    """Replaces test_refuses_empty_block: there is nothing to write without one."""
    assert not ledger.requests_dir.exists() or not list(ledger.requests_dir.glob("*.json"))
    from aikiri_ledger import cli
    with pytest.raises(SystemExit):
        cli.main(["--ledger", str(ledger.root), "block", "--keyfile", "/nonexistent"])


def test_append_only(ledger, key, mac, journal):
    add(ledger, key, mac, sha256_file(journal))
    with pytest.raises(FileExistsError):
        ledger._append(ledger.read(1))


def test_tamper_detected(ledger, key, mac, journal, trust):
    add(ledger, key, mac, sha256_file(journal))
    p = ledger.blocks_dir / "000001.json"
    d = json.loads(p.read_text())
    d["timestamp"] = "2019-01-01T00:00:00+08:00"  # backdate attempt
    p.write_text(json.dumps(d))
    state, report = verify_chain(ledger, trust)
    assert state == State.INVALID and any("block 1" in r for r in report)


def test_a_stranger_signing_a_block_is_rejected(ledger, key, mac, journal, trust):
    """Replaces test_wrong_key_rejected, whose assertion was the bug: it accepted
    any consistent signer and left validator identity to a witness that was never
    consulted. The validator is now pinned in the trust anchor."""
    imposter = new_key()
    r = Request.build(index=1, prev_hash=ledger.head().hash,
                      roots=[{"kind": "journal", "sha256": sha256_file(journal)}],
                      nonce="ab" * 32, validator=imposter.verify_key.encode().hex(),
                      approver=mac)
    ledger.append_from_request(r, imposter, now=datetime(2026, 9, 3, tzinfo=MANILA),
                               registered=[mac.as_key()])
    state, report = verify_chain(ledger, trust)
    assert state == State.INVALID and any("validator" in r for r in report)


def test_revocation_root(ledger, key, mac, trust):
    add(ledger, key, mac, "a" * 64, kind="scenario", nonce="11" * 32,
        now=datetime(2026, 9, 3, tzinfo=MANILA))
    add(ledger, key, mac, "b" * 64, kind="revocation", nonce="22" * 32,
        now=datetime(2026, 9, 4, tzinfo=MANILA))
    state, report = verify_chain(ledger, trust)
    assert state == State.VALID_LOCALLY, report
    assert len(list(ledger.blocks())) == 3
    assert ledger.read(2).roots[0]["kind"] == "revocation"


def test_merkle_root_is_v1_only(ledger, key, mac, journal):
    """Kept because blocks 0 and 1 carry one. v2 blocks do not."""
    assert merkle_root([]) == ledger.read(0).raw["merkle_root"]
    b = add(ledger, key, mac, sha256_file(journal))
    assert "merkle_root" not in b.raw


def test_keygen_refuses_a_path_inside_the_repository(tmp_path, monkeypatch):
    from aikiri_ledger import cli
    monkeypatch.chdir(Path(__file__).resolve().parent.parent)
    with pytest.raises(SystemExit):
        cli.main(["keygen", "--keyfile", "ledger/chii.key"])
    assert not Path("ledger/chii.key").exists()


# ------------------------------------------------------------- Base witness ----
@pytest.fixture(scope="module")
def compiled():
    return compile_contract()


@pytest.fixture
def base(compiled):
    return Web3(EthereumTesterProvider()), compiled


def test_contract_deploy_and_anchor(ledger, key, mac, journal, base):
    w3, compiled = base
    chii = w3.eth.accounts[0]
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    addr = bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    assert addr and bw.matches(ledger.read(0))
    b1 = add(ledger, key, mac, sha256_file(journal))
    tx = bw.anchor(b1)
    assert tx and bw.matches(b1) and bw.latest_index() == 1
    rec = bw.record(1)
    assert rec["blockHash"] == b1.hash and rec["by"] == chii


def test_contract_rejects_reanchor_and_gaps(ledger, key, mac, journal, base):
    w3, compiled = base
    bw = BaseWitness(w3, None, compiled["abi"], account=w3.eth.accounts[0])
    bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    b1 = add(ledger, key, mac, sha256_file(journal), now=datetime(2026, 9, 3, tzinfo=MANILA))
    bw.anchor(b1)
    with pytest.raises(Exception):  # AlreadyAnchored
        bw.anchor(b1)
    b2 = add(ledger, key, mac, "c" * 64, nonce="dd" * 32, now=datetime(2026, 9, 4, tzinfo=MANILA))
    b3 = add(ledger, key, mac, "d" * 64, nonce="ee" * 32, now=datetime(2026, 9, 5, tzinfo=MANILA))
    with pytest.raises(Exception):  # NotSequential: 3 before 2
        bw.anchor(b3)
    bw.anchor(b2)
    bw.anchor(b3)
    assert bw.matches(b3)


def test_contract_only_owner(ledger, key, mac, journal, base):
    w3, compiled = base
    chii, stranger = w3.eth.accounts[0], w3.eth.accounts[1]
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    addr = bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    b1 = add(ledger, key, mac, sha256_file(journal))
    imposter = BaseWitness(w3, addr, compiled["abi"], account=stranger)
    with pytest.raises(Exception):  # NotOwner
        imposter.anchor(b1)
    assert not imposter.matches(b1)


def test_full_verifier_detects_a_re_signed_rewrite(ledger, key, mac, journal, base, trust):
    w3, compiled = base
    bw = BaseWitness(w3, None, compiled["abi"], account=w3.eth.accounts[0])
    addr = bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    trust.contract, trust.owner = addr, w3.eth.accounts[0]
    b1 = add(ledger, key, mac, sha256_file(journal))
    bw.anchor(b1)
    state, report = verify_all(ledger, trust, base=bw)
    assert state == State.BASE_VERIFIED, report

    # Rewrite block 1 and re-sign it with the same validator key. The chain alone
    # accepts that; the approval and the witness do not.
    d = json.loads((ledger.blocks_dir / "000001.json").read_text())
    d["roots"] = [{"kind": "journal", "sha256": "e" * 64}]
    body = {k: v for k, v in d.items() if k not in ("signature", "hash")}
    from aikiri_ledger.canonical import domain_hash, BLOCK_DOMAIN_V2
    d["hash"] = domain_hash(BLOCK_DOMAIN_V2, body)
    d["signature"] = key.sign(bytes.fromhex(d["hash"])).signature.hex()
    (ledger.blocks_dir / "000001.json").write_text(json.dumps(d, indent=2, sort_keys=True))
    ledger.head_path.write_text(f"1 {d['hash']}\n")

    state, report = verify_chain(ledger, trust)
    assert state == State.INVALID and any("approval" in r for r in report), \
        "a re-signed rewrite must fail on the approval, before any witness is asked"
    state, report = verify_all(ledger, trust, base=bw)
    assert state == State.INVALID


# ------------------------------------------------- keys from env, raw signing ----
def test_validator_key_from_env(monkeypatch):
    from aikiri_ledger.chain import parse_key, key_from_env
    sk = new_key()
    seed = sk.encode().hex()
    for form in (seed, "0x" + seed, seed.upper()):
        assert parse_key(form).verify_key == sk.verify_key
    import base64
    assert parse_key(base64.b64encode(sk.encode()).decode()).verify_key == sk.verify_key
    with pytest.raises(ValueError):
        parse_key("not a key")
    monkeypatch.setenv("AIKIRI_VALIDATOR_KEY", seed)
    assert key_from_env().verify_key == sk.verify_key
    monkeypatch.delenv("AIKIRI_VALIDATOR_KEY")
    assert key_from_env() is None


def test_deploy_with_private_key_signs_locally(ledger, base):
    w3, compiled = base
    pk = w3.provider.ethereum_tester.backend.account_keys[0].to_hex()
    bw = BaseWitness(w3, None, compiled["abi"], private_key=pk)
    assert bw.account == w3.eth.accounts[0]
    addr = bw.deploy(ledger.read(0).hash, compiled["bytecode"], max_fee_eth=1.0)
    assert bw.matches(ledger.read(0)) and bw.genesis_hash() == ledger.read(0).hash
    assert bw.owner() == bw.account and bw.address == addr
    from aikiri_ledger.witness import receipt_cost
    cost = receipt_cost(bw.last_receipt)
    assert cost["gasUsed"] > 0 and cost["totalWei"] >= cost["l2FeeWei"]
    with pytest.raises(ValueError):
        BaseWitness(w3, addr, compiled["abi"], account=w3.eth.accounts[1], private_key=pk)
    with pytest.raises(RuntimeError):
        BaseWitness(w3, None, compiled["abi"], private_key=pk).deploy(
            ledger.read(0).hash, compiled["bytecode"], max_fee_eth=0.0)


def test_cli_init_from_env_and_refuses_keygen_in_ci(monkeypatch, tmp_path):
    from aikiri_ledger import cli
    sk = new_key()
    monkeypatch.setenv("AIKIRI_VALIDATOR_KEY", sk.encode().hex())
    assert cli.main(["--ledger", str(tmp_path / "l1"), "init", "--keyfile",
                     str(tmp_path / "nope.key")]) == 0
    assert Ledger(tmp_path / "l1").read(0).validator == sk.verify_key.encode().hex()
    assert not (tmp_path / "nope.key").exists()
    monkeypatch.delenv("AIKIRI_VALIDATOR_KEY")
    monkeypatch.setattr(cli, "IN_CI", True)
    with pytest.raises(SystemExit):
        cli.main(["--ledger", str(tmp_path / "l2"), "init", "--keyfile", str(tmp_path / "nope.key")])
    assert not (tmp_path / "nope.key").exists()


def test_find_existing_deployment_without_sending(ledger, base):
    from aikiri_ledger.witness import find_deployment, create_address, wait_for_code, find_creation_block
    w3, compiled = base
    chii = w3.eth.accounts[0]
    g = ledger.read(0)
    assert find_deployment(w3, chii, compiled["abi"], g.hash) is None
    w3.eth.send_transaction({"from": chii, "to": w3.eth.accounts[1], "value": 1})
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    addr = bw.deploy(g.hash, compiled["bytecode"])
    assert addr == create_address(chii, 1)
    assert wait_for_code(w3, addr, timeout=1)
    for _ in range(3):
        w3.eth.send_transaction({"from": chii, "to": w3.eth.accounts[1], "value": 1})
    assert find_creation_block(w3, addr) == bw.last_receipt["blockNumber"]
    found = find_deployment(w3, chii, compiled["abi"], g.hash)
    assert found is not None and found[0] == addr
    assert found[1]["transactionHash"] == bw.last_receipt["transactionHash"]
    assert find_deployment(w3, chii, compiled["abi"], "f" * 64) is None


def test_base_receipt_carries_cost_and_no_content(ledger, key, mac, journal, base):
    from aikiri_ledger.witness import write_base_receipt
    w3, compiled = base
    bw = BaseWitness(w3, None, compiled["abi"], account=w3.eth.accounts[0])
    bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    b1 = add(ledger, key, mac, sha256_file(journal))
    tx = bw.anchor(b1)
    p = write_base_receipt(ledger, b1, tx, bw.address, 8453, rcpt=bw.last_receipt)
    d = json.loads(p.read_text())
    assert d["index"] == 1 and d["hash"] == b1.hash and d["tx"] == tx
    assert d["gasUsed"] > 0 and d["baseBlock"] > 0
    assert "journal" not in p.read_text() and "ref" not in p.read_text()
