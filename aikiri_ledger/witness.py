"""Witnesses for the Aikiri chain.

A block is believed because strangers committed to its hash. Two witnesses:
  Base    ~ AikiriLedger.sol, Chii's own contract. Cents per block.
  Bitcoin ~ OpenTimestamps. Free. Proof file kept beside the block.

A receipt never depends on a single chain to be believed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from web3 import Web3

from .chain import Ledger, Block
from .errors import QuorumError

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


    @property
    def address(self):
        return self.contract.address if self.contract else None

    def matches(self, block: Block, block_identifier=None) -> bool:
        if not self.contract:
            return False
        call = self.contract.functions.matches(block.index, bytes.fromhex(block.hash))
        return bool(call.call(block_identifier=block_identifier)
                    if block_identifier is not None else call.call())

    def latest_index(self, block_identifier=None) -> int:
        call = self.contract.functions.latestIndex()
        return int(call.call(block_identifier=block_identifier)
                   if block_identifier is not None else call.call())

    def code_hash(self, block_identifier=None) -> str:
        """keccak of the deployed bytecode, bare lowercase hex ~ the form a pin
        is stored in. Read at a height when one is given, so a quorum compares
        the same code, not whatever each node has most recently seen."""
        from eth_utils import keccak
        addr = self.address
        if addr is None:
            raise ValueError("no contract to read code from")
        code = (self.w3.eth.get_code(addr, block_identifier=block_identifier)
                if block_identifier is not None else self.w3.eth.get_code(addr))
        return keccak(bytes(code)).hex()

    def finalized_block(self) -> int:
        """The height both sides of a quorum can agree on.

        No fallback to the head: an unfinalized height can be reorged away, and a
        node that cannot answer what is final does not get a vote on what is final.
        `QuorumBase.common_block` already tolerates an endpoint that cannot answer;
        answering with the wrong number is what it cannot tolerate."""
        return int(self.w3.eth.get_block("finalized")["number"])

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
def _plain(text: str) -> str:
    """What ots said, as one line of printable ASCII, for a log or a commit."""
    return re.sub(r"[^ -~]", "?", text)[:200]


class OtsError(RuntimeError):
    """ots failed to run, as opposed to reading a file and finding no proof in it."""


class BitcoinWitness:
    """Wraps the `ots` CLI (opentimestamps-client). Needs network for stamp/upgrade;
    a completed .ots proof verifies against Bitcoin alone, forever."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger

    @staticmethod
    def available() -> bool:
        return shutil.which("ots") is not None

    def _digest_file(self, block: Block) -> Path:
        """Written beside and then moved over, so a write that fails never leaves the
        .hash cut short."""
        self.ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
        p = self.ledger.proof_path(block.index, "hash")
        tmp = p.with_name(p.name + ".tmp")
        try:
            tmp.unlink(missing_ok=True)  # a link left there is removed, never written through
            data = bytes.fromhex(block.hash)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            try:
                if os.write(fd, data) != len(data):
                    raise OSError(f"short write to {tmp.name}")
            finally:
                os.close(fd)
            os.replace(tmp, p)
        finally:
            tmp.unlink(missing_ok=True)
        return p

    def stamp(self, block: Block) -> Path:
        """Creates <index>.hash.ots (pending until upgraded). `ots stamp` creates the
        .ots before it writes the proof into it, so when it fails, whatever it left
        is removed: a cut-short .ots is not a proof, is left for a person to look at,
        and the block would never be stamped again; a lone .hash would ride into a
        commit on its own."""
        ots = self.ledger.proof_path(block.index, "hash.ots")
        digest = self.ledger.proof_path(block.index, "hash")
        # The cleanup removes only what this run made. _digest_file replaces
        # whatever is at .hash (a link included) with this run's own file, which
        # goes unless a real .hash was there before; the cleanup itself never
        # removes a link, since this run makes none.
        had = os.path.lexists(ots), digest.exists() and not digest.is_symlink()
        try:
            p = self._digest_file(block)
            subprocess.run(["ots", "stamp", str(p)], check=True)
        except BaseException:  # a failure, or an interrupt: what it left goes either way
            for path, existed in zip((ots, digest), had):
                if not existed and not path.is_symlink():  # this run makes no links
                    path.unlink(missing_ok=True)
            raise
        return ots

    def upgrade(self, block: Block) -> str:
        """What is on disk decides first. A changed .ots that is a proof of this
        block is an upgrade however ots exited: "upgraded, complete" on exit 0,
        "upgraded, still pending" when ots says so, and otherwise "upgraded, not
        called complete". An unchanged one is "complete" on exit 0 and "pending"
        only on ots's own words for it; any other failure is OtsError.
        "blocked" when settle_backup leaves a .bak (neither file a proof), and
        "no proof" when the .ots is not a proof of this block."""
        ots = self.ledger.proof_path(block.index, "hash.ots")
        bak = ots.with_name(ots.name + ".bak")
        if not self.settle_backup(block):  # a .bak left, and neither file is a proof
            return "blocked"
        if not self.holds_proof(block):  # missing, a link, junk or another block's
            return "no proof"
        before = ots.read_bytes()
        try:
            r = subprocess.run(["ots", "upgrade", str(ots)], capture_output=True,
                               text=True, errors="replace")  # what ots says is never a reason to crash
        except OSError as e:  # on PATH but cannot be executed: it renamed nothing
            raise OtsError(f"ots upgrade did not run: {_plain(str(e))}") from e
        try:
            self.settle_backup(block)
        except OtsError:
            # Settled above, so any .bak now is the proof ots just renamed, and what
            # it wrote in its place cannot be checked: the proof goes back.
            if bak.exists():
                os.replace(bak, ots)
            raise
        said = [l.strip() for l in (r.stderr or "").splitlines() if l.strip()]
        # ots's own words for a proof with no Bitcoin attestation yet
        # (otsclient/cmds.py upgrade_command); it prints them only with exit 1
        incomplete = r.returncode == 1 and "failed! timestamp not complete" in (l.lower() for l in said)
        if os.path.lexists(ots) and ots.read_bytes() != before and self.holds_proof(block):
            if r.returncode == 0:
                return "upgraded, complete"
            if incomplete:
                return "upgraded, still pending"
            return f"upgraded, not called complete: ots exited {r.returncode}"
        if r.returncode == 0:
            return "complete"
        if incomplete:
            return "pending"
        raise OtsError(f"ots upgrade failed, exit {r.returncode}" + (f": {_plain(said[-1])}" if said else ""))

    def settle_backup(self, block: Block) -> bool:
        """`ots upgrade`, when it has something new, renames the proof to <name>.bak,
        creates the new file and writes the upgraded proof into it; it will not
        write an upgrade while a real .bak is there (it checks with exists(), so a
        dangling link does not stop it). If the proof reads as one, it is that
        upgrade's output, holding every attestation the backup had, and the backup
        goes. If it is missing, does not read as a proof (the write failed part-way),
        or is not a proof of this block, and the backup is one, the backup is the good
        copy and is put back over it. If neither is, both are left and it returns
        False: nothing may be stamped then, or the new proof would read as that
        backup's upgrade and the next settle would delete the backup. Every command
        that writes a proof settles first, so a .bak is never left beside a proof it
        did not come from."""
        ots = self.ledger.proof_path(block.index, "hash.ots")
        bak = ots.with_name(ots.name + ".bak")
        if not os.path.lexists(bak):  # a link there, even dangling, is a .bak that is no proof
            return True
        if self.holds_proof(block):
            bak.unlink()
        elif self.proof_of(bak, block):
            os.replace(bak, ots)
        else:
            return False  # neither is a proof of this block: both stay, to be looked at
        return True

    def holds_proof(self, block: Block) -> bool:
        """The .ots is there, reads as a proof, and is a proof of this block."""
        return self.proof_of(self.ledger.proof_path(block.index, "hash.ots"), block)

    @staticmethod
    def proof_of(path: Path, block: Block) -> bool:
        """`ots info` names the digest a proof is of, which must be this block's, and
        says so when the file is not a proof at all (otsclient/cmds.py info_command).
        Any other failure is ots not running, which says nothing about the file: it
        raises OtsError, and nothing is stamped over, put back or deleted on it,
        save in upgrade: there the .bak is the proof ots itself just renamed."""
        if path.is_symlink() or not path.exists():
            return False  # a link is never a proof: what it points to is not what is committed
        try:
            r = subprocess.run(["ots", "info", str(path)], capture_output=True,
                               text=True, errors="replace")  # what ots says is never a reason to crash
        except OSError as e:  # on PATH but cannot be executed
            raise OtsError(f"ots info did not run: {_plain(str(e))}") from e
        if r.returncode == 0:
            digest = hashlib.sha256(bytes.fromhex(block.hash)).hexdigest()
            first = (r.stdout.splitlines() or [""])[0].strip().lower()
            return first == f"file sha256 hash: {digest}"
        for line in (r.stderr or "").splitlines():
            line = line.strip().lower()
            if (line.startswith("error! ") and line.endswith("is not a timestamp file.")) \
                    or line.startswith("invalid timestamp file "):
                return False
        said = [l.strip() for l in (r.stderr or r.stdout or "").splitlines() if l.strip()]
        raise OtsError(f"ots info did not run, exit {r.returncode}" + (f": {_plain(said[-1])}" if said else ""))

    def verify(self, block: Block) -> tuple[bool, str]:
        ots = self.ledger.proof_path(block.index, "hash.ots")
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
    """Proof beside the block, in proofs/: which tx on which contract anchored which
    hash, plus what it cost. Numbers and hashes only."""
    ledger.proofs_dir.mkdir(parents=True, exist_ok=True)
    p = ledger.proof_path(block.index, "base.json")
    d = {"index": block.index, "hash": block.hash, "tx": tx_hash, "contract": contract_address, "chainId": chain_id}
    if rcpt is not None:
        d["baseBlock"] = int(rcpt["blockNumber"])
        d.update(receipt_cost(rcpt))
    p.write_text(json.dumps(d, indent=2) + "\n")
    return p


class QuorumBase:
    """Several independent readers of the same contract.

    One RPC is one party's word. Requiring every endpoint to answer makes a
    verifier that fails whenever a provider is down; requiring none makes a
    verifier that believes whoever answers first. So: a majority must answer,
    at a block height they all have, and they must agree. Disagreement is never
    a success ~ it is the loudest possible signal that something is wrong.
    """

    def __init__(self, readers, quorum: int | None = None):
        if not readers:
            raise QuorumError("no RPC endpoints given")
        self.readers = list(readers)
        self.quorum = quorum or (len(self.readers) // 2 + 1)

    def _gather(self, fn):
        answers, errors = [], []
        for r in self.readers:
            try:
                answers.append(fn(r))
            except Exception as e:  # noqa: BLE001 - an endpoint that cannot answer does not vote
                errors.append(repr(e))
        if len(answers) < self.quorum:
            raise QuorumError(f"{len(answers)} of {len(self.readers)} endpoints answered; "
                              f"{self.quorum} needed. {'; '.join(errors)}")
        distinct = {repr(a) for a in answers}
        if len(distinct) > 1:
            raise QuorumError(f"endpoints disagree: {sorted(distinct)}")
        return answers[0]

    def common_block(self) -> int:
        heights = []
        for r in self.readers:
            try:
                heights.append(int(r.finalized_block()))
            except Exception:  # noqa: BLE001
                pass
        if len(heights) < self.quorum:
            raise QuorumError(f"{len(heights)} of {len(self.readers)} endpoints reported a "
                              f"finalized block; {self.quorum} needed. Reading at each node's "
                              f"own head instead would drop the guarantee this class exists for")
        return min(heights)

    # ---- the read interface the verifier uses ----
    @property
    def address(self):
        return getattr(self.readers[0], "address", None)

    def latest_index(self) -> int:
        at = self.common_block()
        return self._gather(lambda r: r.latest_index(at))

    def matches(self, block) -> bool:
        at = self.common_block()
        return self._gather(lambda r: r.matches(block, at))

    def code_hash(self):
        at = self.common_block()
        return self._gather(lambda r: r.code_hash(at))

    def genesis_hash(self):
        return self._gather(lambda r: r.genesis_hash())

    def owner(self):
        return self._gather(lambda r: r.owner())

    def record(self, index: int) -> dict:
        return self._gather(lambda r: r.record(index))

