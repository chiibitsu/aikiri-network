"""Witnesses for the Aikiri chain.

A block is believed because strangers committed to its hash. Two witnesses:
  Base    ~ AikiriLedger.sol, Chii's own contract. Cents per block.
  Bitcoin ~ OpenTimestamps. Free. Proof file kept beside the block.

A receipt never depends on a single chain to be believed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from web3 import Web3

from .chain import Ledger, Block

CONTRACT_SRC = Path(__file__).resolve().parent.parent / "contracts" / "AikiriLedger.sol"


# ---------------------------------------------------------------- Base ----
def compile_contract() -> dict:
    """Compile AikiriLedger.sol with solc 0.8.26. Returns {abi, bytecode}."""
    import solcx

    version = "0.8.26"
    if version not in [str(v) for v in solcx.get_installed_solc_versions()]:
        solcx.install_solc(version)
    solcx.set_solc_version(version)
    out = solcx.compile_source(
        CONTRACT_SRC.read_text(),
        output_values=["abi", "bin"],
        solc_version=version,
        optimize=True,
        optimize_runs=200,
    )
    key = next(k for k in out if k.endswith(":AikiriLedger"))
    return {"abi": out[key]["abi"], "bytecode": out[key]["bin"]}


BASE_KEY_ENV = "BASE_PRIVATE_KEY"


def base_key_from_env(var: str = BASE_KEY_ENV) -> str | None:
    """Wallet private key from the environment (GitHub Actions secret), or None."""
    v = os.environ.get(var, "").strip()
    if not v:
        return None
    if not v.startswith("0x"):
        v = "0x" + v
    return v


class BaseWitness:
    """Talks to the AikiriLedger contract. Read-only unless a signer is given.

    Two ways to sign: an unlocked node account (`account`, used by the in-process
    EVM in tests) or a local private key (`private_key`, used against a public RPC
    in production). With a private key, transactions are signed here and sent raw;
    the key never leaves the process."""

    def __init__(self, w3: Web3, address: str | None, abi: list, account: str | None = None,
                 private_key: str | None = None):
        self.w3 = w3
        self.abi = abi
        self.last_receipt = None
        if private_key:
            from web3.middleware import SignAndSendRawMiddlewareBuilder
            acct = w3.eth.account.from_key(private_key)
            try:
                w3.middleware_onion.remove("aikiri-signer")
            except (KeyError, ValueError):
                pass
            w3.middleware_onion.inject(SignAndSendRawMiddlewareBuilder.build(acct), name="aikiri-signer", layer=0)
            if account and account.lower() != acct.address.lower():
                raise ValueError(f"private key derives {acct.address}, config says {account}")
            account = acct.address
        self.account = account
        self.contract = w3.eth.contract(address=address, abi=abi) if address else None

    def deploy(self, genesis_hash_hex: str, bytecode: str, max_fee_eth: float | None = None) -> str:
        """Deploy with the genesis hash baked in. `max_fee_eth` aborts before sending
        if estimated gas * maxFeePerGas exceeds it. Receipt kept in `last_receipt`."""
        if not self.account:
            raise ValueError("deploy needs a signer account")
        factory = self.w3.eth.contract(abi=self.abi, bytecode=bytecode)
        ctor = factory.constructor(bytes.fromhex(genesis_hash_hex))
        if max_fee_eth is not None:
            gas = ctor.estimate_gas({"from": self.account})
            fee_cap = self.w3.eth.gas_price * 2
            worst = self.w3.from_wei(gas * fee_cap, "ether")
            if worst > max_fee_eth:
                raise RuntimeError(f"refusing to deploy: worst-case fee {worst} ETH > cap {max_fee_eth} ETH")
        tx = ctor.transact({"from": self.account})
        rcpt = self.w3.eth.wait_for_transaction_receipt(tx)
        if rcpt.status != 1:
            raise RuntimeError("deploy tx failed")
        self.last_receipt = rcpt
        self.contract = self.w3.eth.contract(address=rcpt.contractAddress, abi=self.abi)
        return rcpt.contractAddress

    def anchor(self, block: Block) -> str:
        if not self.account or not self.contract:
            raise ValueError("anchor needs a signer account and a deployed contract")
        tx = self.contract.functions.anchor(block.index, bytes.fromhex(block.hash)).transact({"from": self.account})
        rcpt = self.w3.eth.wait_for_transaction_receipt(tx)
        if rcpt.status != 1:
            raise RuntimeError(f"anchor tx failed for block {block.index}")
        self.last_receipt = rcpt
        return rcpt.transactionHash.hex()

    def genesis_hash(self) -> str:
        return self.contract.functions.genesisHash().call().hex()

    def owner(self) -> str:
        return self.contract.functions.owner().call()


    def matches(self, block: Block) -> bool:
        if not self.contract:
            return False
        return bool(self.contract.functions.matches(block.index, bytes.fromhex(block.hash)).call())

    def record(self, index: int) -> dict:
        h, at, by = self.contract.functions.blocks(index).call()
        return {"blockHash": h.hex(), "anchoredAt": int(at), "by": by}


def create_address(deployer: str, nonce: int) -> str:
    """Address a CREATE from `deployer` at `nonce` lands on: keccak(rlp([sender, nonce]))[12:]."""
    import rlp
    from eth_utils import keccak, to_checksum_address
    raw = keccak(rlp.encode([bytes.fromhex(deployer[2:]), nonce]))[12:]
    return to_checksum_address(raw)


def wait_for_code(w3: Web3, address: str, timeout: float = 120.0, poll: float = 3.0) -> bool:
    """Public RPCs are load balanced; the node that mined the receipt is not always
    the node that answers the next call. Wait until code is visible at `address`."""
    import time
    deadline = time.monotonic() + timeout
    while True:
        if w3.eth.get_code(address):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def find_creation_block(w3: Web3, address: str) -> int:
    """First block where `address` has code. Binary search over eth_getCode, so it
    never asks a public RPC for a wide log range."""
    lo, hi = 0, w3.eth.block_number
    while lo < hi:
        mid = (lo + hi) // 2
        if w3.eth.get_code(address, block_identifier=mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


def find_deployment(w3: Web3, deployer: str, abi: list, genesis_hash_hex: str, max_nonce: int = 64):
    """Look for an AikiriLedger already deployed by `deployer` that carries this
    genesis hash, by walking its past nonces. Returns (address, creation receipt)
    or None. Sends nothing."""
    nonce = w3.eth.get_transaction_count(deployer)
    for n in range(min(nonce, max_nonce)):
        addr = create_address(deployer, n)
        if not w3.eth.get_code(addr):
            continue
        c = w3.eth.contract(address=addr, abi=abi)
        try:
            if c.functions.genesisHash().call().hex() != genesis_hash_hex:
                continue
        except Exception:
            continue
        born = find_creation_block(w3, addr)
        logs = c.events.Anchored().get_logs(from_block=born, to_block=born, argument_filters={"index": 0})
        rcpt = w3.eth.get_transaction_receipt(logs[0]["transactionHash"]) if logs else None
        return addr, rcpt
    return None


def receipt_cost(rcpt) -> dict:
    """Gas actually paid, in wei. Base (OP Stack) receipts also carry an L1 data fee."""
    l2 = int(rcpt["gasUsed"]) * int(rcpt.get("effectiveGasPrice", 0))
    l1_raw = rcpt.get("l1Fee", 0) or 0
    l1 = int(l1_raw, 16) if isinstance(l1_raw, str) else int(l1_raw)
    return {"gasUsed": int(rcpt["gasUsed"]), "effectiveGasPrice": int(rcpt.get("effectiveGasPrice", 0)),
            "l2FeeWei": l2, "l1FeeWei": l1, "totalWei": l2 + l1}


# ------------------------------------------------------------- Bitcoin ----
class BitcoinWitness:
    """Wraps the `ots` CLI (opentimestamps-client). Needs network for stamp/upgrade;
    a completed .ots proof verifies against Bitcoin alone, forever."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger

    @staticmethod
    def available() -> bool:
        return shutil.which("ots") is not None

    def _digest_file(self, block: Block) -> Path:
        p = self.ledger.blocks_dir / f"{block.index:06d}.hash"
        p.write_bytes(bytes.fromhex(block.hash))
        return p

    def stamp(self, block: Block) -> Path:
        """Creates <index>.hash.ots (pending until upgraded)."""
        p = self._digest_file(block)
        subprocess.run(["ots", "stamp", str(p)], check=True)
        return p.with_suffix(".hash.ots")

    def upgrade(self, block: Block) -> bool:
        ots = self.ledger.blocks_dir / f"{block.index:06d}.hash.ots"
        r = subprocess.run(["ots", "upgrade", str(ots)], capture_output=True, text=True)
        return r.returncode == 0

    def verify(self, block: Block) -> tuple[bool, str]:
        ots = self.ledger.blocks_dir / f"{block.index:06d}.hash.ots"
        if not ots.exists():
            return False, "no .ots proof"
        r = subprocess.run(["ots", "verify", str(ots)], capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()


# ------------------------------------------------------------ Verifier ----
def verify_all(ledger: Ledger, base: BaseWitness | None = None, bitcoin: BitcoinWitness | None = None) -> tuple[bool, list[str]]:
    """Chain → signatures → Base anchors → Bitcoin proofs. Stops at first failure."""
    ok, report = ledger.verify()
    if not ok:
        return False, report
    if base is not None:
        for b in ledger.blocks():
            if base.matches(b):
                report.append(f"block {b.index}: Base witness ok")
            else:
                report.append(f"block {b.index}: Base witness MISSING or MISMATCH")
                return False, report
    if bitcoin is not None:
        for b in ledger.blocks():
            good, msg = bitcoin.verify(b)
            report.append(f"block {b.index}: Bitcoin witness {'ok' if good else 'pending/missing'}")
    return True, report


def write_base_receipt(ledger: Ledger, block: Block, tx_hash: str, contract_address: str, chain_id: int, rcpt=None) -> Path:
    """Proof file beside the block: which tx on which contract anchored which hash,
    plus what it cost. Numbers and hashes only."""
    p = ledger.blocks_dir / f"{block.index:06d}.base.json"
    d = {"index": block.index, "hash": block.hash, "tx": tx_hash, "contract": contract_address, "chainId": chain_id}
    if rcpt is not None:
        d["baseBlock"] = int(rcpt["blockNumber"])
        d.update(receipt_cost(rcpt))
    p.write_text(json.dumps(d, indent=2) + "\n")
    return p
