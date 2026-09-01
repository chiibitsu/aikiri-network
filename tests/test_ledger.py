import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from web3 import Web3, EthereumTesterProvider

from aikiri_ledger.chain import Ledger, Root, new_key, save_key, load_key, sha256_file, merkle_root, MANILA
from aikiri_ledger.witness import compile_contract, BaseWitness, verify_all


@pytest.fixture
def key(tmp_path):
    sk = new_key()
    save_key(sk, tmp_path / "keys" / "chii.key")
    return load_key(tmp_path / "keys" / "chii.key")


@pytest.fixture
def ledger(tmp_path, key):
    L = Ledger(tmp_path / "ledger")
    L.init(key, now=datetime(2026, 9, 2, 2, 32, tzinfo=MANILA))
    return L


@pytest.fixture
def journal(tmp_path):
    p = tmp_path / "decision-journal.md"
    p.write_text("## 2026-09-02\n- I am deciding to dive deeper into the Aikiri Network's very reason for existing.\n")
    return p


def test_genesis_and_verify(ledger):
    ok, report = ledger.verify()
    assert ok, report
    g = ledger.read(0)
    assert g.index == 0 and g.roots == [] and len(g.hash) == 64


def test_seal_and_block(ledger, key, journal):
    ledger.seal(Root(kind="journal", sha256=sha256_file(journal), ref="03_human/journal/decision-journal.md"))
    b = ledger.block(key, now=datetime(2026, 9, 2, 23, 59, tzinfo=MANILA))
    assert b.index == 1 and b.prev_hash == ledger.read(0).hash
    assert b.merkle_root == merkle_root([b.roots[0]["sha256"]])
    ok, report = ledger.verify()
    assert ok, report
    assert not ledger.queue()  # queue cleared


def test_refuses_empty_block(ledger, key):
    with pytest.raises(ValueError):
        ledger.block(key)


def test_append_only(ledger, key, journal):
    ledger.seal(Root(kind="journal", sha256=sha256_file(journal)))
    ledger.block(key)
    with pytest.raises(FileExistsError):
        ledger._append(ledger.read(1))


def test_tamper_detected(ledger, key, journal):
    ledger.seal(Root(kind="journal", sha256=sha256_file(journal)))
    ledger.block(key)
    p = ledger.blocks_dir / "000001.json"
    d = json.loads(p.read_text())
    d["timestamp"] = "2019-01-01T00:00:00+08:00"  # backdate attempt
    p.write_text(json.dumps(d, indent=2))
    ok, report = ledger.verify()
    assert not ok and "block 1" in report[-1]


def test_wrong_key_rejected(ledger, journal):
    imposter = new_key()
    ledger.seal(Root(kind="journal", sha256=sha256_file(journal)))
    ledger.block(imposter)  # signs fine, but...
    ok, _ = ledger.verify()
    assert ok  # ...chain verify accepts any consistent signer; validator identity is enforced by the Base contract (owner) in v1
    assert ledger.read(1).validator != ledger.read(0).validator


def test_revocation_root(ledger, key):
    ledger.seal(Root(kind="scenario", sha256="a" * 64, ref="scn-1"))
    ledger.block(key, now=datetime(2026, 9, 3, tzinfo=MANILA))
    ledger.seal(Root(kind="revocation", sha256="b" * 64, ref="of:scn-1"))
    ledger.block(key, now=datetime(2026, 9, 4, tzinfo=MANILA))
    ok, report = ledger.verify()
    assert ok and len(list(ledger.blocks())) == 3


# ------------------------------------------------------------- Base witness ----
@pytest.fixture(scope="module")
def compiled():
    return compile_contract()


@pytest.fixture
def base(compiled):
    w3 = Web3(EthereumTesterProvider())
    return w3, compiled


def test_contract_deploy_and_anchor(ledger, key, journal, base):
    w3, compiled = base
    chii = w3.eth.accounts[0]
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    addr = bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    assert addr and bw.matches(ledger.read(0))

    ledger.seal(Root(kind="journal", sha256=sha256_file(journal)))
    b1 = ledger.block(key)
    tx = bw.anchor(b1)
    assert tx and bw.matches(b1)
    rec = bw.record(1)
    assert rec["blockHash"] == b1.hash and rec["by"] == chii


def test_contract_rejects_reanchor_and_gaps(ledger, key, journal, base):
    w3, compiled = base
    chii = w3.eth.accounts[0]
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    ledger.seal(Root(kind="journal", sha256=sha256_file(journal)))
    b1 = ledger.block(key)
    bw.anchor(b1)
    with pytest.raises(Exception):  # AlreadyAnchored
        bw.anchor(b1)
    ledger.seal(Root(kind="journal", sha256="c" * 64))
    b2 = ledger.block(key)
    ledger.seal(Root(kind="journal", sha256="d" * 64))
    b3 = ledger.block(key)
    with pytest.raises(Exception):  # NotSequential: 3 before 2
        bw.anchor(b3)
    bw.anchor(b2)
    bw.anchor(b3)
    assert bw.matches(b3)


def test_contract_only_owner(ledger, key, journal, base):
    w3, compiled = base
    chii, stranger = w3.eth.accounts[0], w3.eth.accounts[1]
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    addr = bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    ledger.seal(Root(kind="journal", sha256=sha256_file(journal)))
    b1 = ledger.block(key)
    imposter = BaseWitness(w3, addr, compiled["abi"], account=stranger)
    with pytest.raises(Exception):  # NotOwner
        imposter.anchor(b1)
    assert not imposter.matches(b1)


def test_full_verifier_detects_unanchored_tamper(ledger, key, journal, base):
    w3, compiled = base
    chii = w3.eth.accounts[0]
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    bw.deploy(ledger.read(0).hash, compiled["bytecode"])
    ledger.seal(Root(kind="journal", sha256=sha256_file(journal)))
    b1 = ledger.block(key)
    bw.anchor(b1)
    ok, report = verify_all(ledger, base=bw)
    assert ok, report

    # Rewrite block 1 consistently (re-sign) ~ chain verify passes, Base witness catches it.
    from aikiri_ledger.chain import Block
    d = json.loads((ledger.blocks_dir / "000001.json").read_text())
    d["roots"] = [{"kind": "journal", "sha256": "e" * 64, "ref": ""}]
    forged = Block(**{k: d[k] for k in Block.__dataclass_fields__}).sign(key)
    (ledger.blocks_dir / "000001.json").write_text(forged.to_json())
    ledger.head_path.write_text(f"1 {forged.hash}\n")
    ok, report = ledger.verify()
    assert ok  # a lone validator can rewrite its own copy...
    ok, report = verify_all(ledger, base=bw)
    assert not ok and "MISMATCH" in report[-1]  # ...but not the witnessed one.


# ------------------------------------------------------- keys from env, raw signing ----
def test_validator_key_from_env(monkeypatch, tmp_path):
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


def test_deploy_with_private_key_signs_locally(ledger, key, journal, base):
    """Production path: a private key signs here and the tx goes out raw."""
    w3, compiled = base
    pk = w3.provider.ethereum_tester.backend.account_keys[0].to_hex()
    bw = BaseWitness(w3, None, compiled["abi"], private_key=pk)
    assert bw.account == w3.eth.accounts[0]
    addr = bw.deploy(ledger.read(0).hash, compiled["bytecode"], max_fee_eth=1.0)
    assert bw.matches(ledger.read(0)) and bw.genesis_hash() == ledger.read(0).hash and bw.owner() == bw.account
    from aikiri_ledger.witness import receipt_cost
    cost = receipt_cost(bw.last_receipt)
    assert cost["gasUsed"] > 0 and cost["totalWei"] >= cost["l2FeeWei"]
    with pytest.raises(ValueError):  # key/config mismatch is refused
        BaseWitness(w3, addr, compiled["abi"], account=w3.eth.accounts[1], private_key=pk)
    with pytest.raises(RuntimeError):  # fee cap
        BaseWitness(w3, None, compiled["abi"], private_key=pk).deploy(ledger.read(0).hash, compiled["bytecode"], max_fee_eth=0.0)


def test_cli_init_from_env_and_refuses_keygen_in_ci(monkeypatch, tmp_path):
    from aikiri_ledger import cli
    sk = new_key()
    monkeypatch.setenv("AIKIRI_VALIDATOR_KEY", sk.encode().hex())
    assert cli.main(["--ledger", str(tmp_path / "l1"), "init", "--keyfile", str(tmp_path / "nope.key")]) == 0
    assert Ledger(tmp_path / "l1").read(0).validator == sk.verify_key.encode().hex()
    assert not (tmp_path / "nope.key").exists()
    monkeypatch.delenv("AIKIRI_VALIDATOR_KEY")
    monkeypatch.setattr(cli, "IN_CI", True)
    with pytest.raises(SystemExit):
        cli.main(["--ledger", str(tmp_path / "l2"), "init", "--keyfile", str(tmp_path / "nope.key")])
    assert not (tmp_path / "nope.key").exists()


def test_find_existing_deployment_without_sending(ledger, key, base):
    """If deploy ran but config.json was never written, the next deploy must
    adopt the existing contract instead of sending a second transaction."""
    from aikiri_ledger.witness import find_deployment, create_address, wait_for_code
    w3, compiled = base
    chii = w3.eth.accounts[0]
    g = ledger.read(0)
    assert find_deployment(w3, chii, compiled["abi"], g.hash) is None
    w3.eth.send_transaction({"from": chii, "to": w3.eth.accounts[1], "value": 1})  # nonce 0 is not a CREATE
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    addr = bw.deploy(g.hash, compiled["bytecode"])
    assert addr == create_address(chii, 1)
    assert wait_for_code(w3, addr, timeout=1)
    from aikiri_ledger.witness import find_creation_block
    for _ in range(3):  # bury the deployment under later blocks
        w3.eth.send_transaction({"from": chii, "to": w3.eth.accounts[1], "value": 1})
    assert find_creation_block(w3, addr) == bw.last_receipt["blockNumber"]
    found = find_deployment(w3, chii, compiled["abi"], g.hash)
    assert found is not None and found[0] == addr
    assert found[1]["transactionHash"] == bw.last_receipt["transactionHash"]
    assert find_deployment(w3, chii, compiled["abi"], "f" * 64) is None  # a different genesis is not ours


def test_cli_deploy_adopts_or_refuses(monkeypatch, tmp_path, base):
    """CLI: with --adopt-only and no prior deployment, exit without sending;
    after a deployment exists, deploy adopts it and writes config without sending."""
    from aikiri_ledger import cli
    w3, compiled = base
    chii = w3.eth.accounts[0]
    pk = w3.provider.ethereum_tester.backend.account_keys[0].to_hex()
    sk = new_key(); L = Ledger(tmp_path / "ledger"); L.init(sk)
    monkeypatch.setenv("BASE_PRIVATE_KEY", pk)
    monkeypatch.setattr(cli, "_w3", lambda rpc, chain_id: w3)
    monkeypatch.setattr(cli, "compile_contract", lambda: compiled)
    nonce0 = w3.eth.get_transaction_count(chii)
    with pytest.raises(SystemExit):
        cli.main(["--ledger", str(L.root), "deploy", "--rpc", "x", "--chain-id", "1", "--adopt-only"])
    assert w3.eth.get_transaction_count(chii) == nonce0 and not (L.root / "config.json").exists()
    bw = BaseWitness(w3, None, compiled["abi"], account=chii)
    addr = bw.deploy(L.read(0).hash, compiled["bytecode"])
    nonce1 = w3.eth.get_transaction_count(chii)
    assert cli.main(["--ledger", str(L.root), "deploy", "--rpc", "x", "--chain-id", "1", "--adopt-only"]) == 0
    assert w3.eth.get_transaction_count(chii) == nonce1  # nothing sent
    cfg = json.loads((L.root / "config.json").read_text())
    dep = json.loads((L.root / "deploy.json").read_text())
    assert cfg["contract"] == addr and cfg["account"] == chii and "key" not in json.dumps(cfg).lower()
    assert dep["contract"] == addr and dep["genesisHash"] == L.read(0).hash and dep["gasUsed"] > 0
    with pytest.raises(SystemExit):  # deployed once
        cli.main(["--ledger", str(L.root), "deploy", "--rpc", "x", "--chain-id", "1"])
