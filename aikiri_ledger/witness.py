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
import threading
import time
from pathlib import Path
from types import SimpleNamespace

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


class StampFailed(subprocess.CalledProcessError):
    """`ots stamp` exited non-zero; its last line, already plain, is the reason."""

    def __init__(self, returncode: int, said: str):
        super().__init__(returncode, ["ots", "stamp"])
        self.said = said

    def __str__(self) -> str:
        return f"ots stamp exited {self.returncode}" + (f": {self.said}" if self.said else "")


class BitcoinWitness:
    """Stamps and upgrades with the `ots` CLI (opentimestamps-client), which needs the
    calendars; verifies by reading the .ots, and a complete one needs only Bitcoin."""

    def __init__(self, ledger: Ledger, public: bool = True):
        self.ledger = ledger
        self.public = public   # ask mempool.space and blockstream.info when no node answers
        self._headers = {}     # height -> header, or why it could not be had, for this run
        self._node_state = None  # not tried yet, the node, or why it cannot answer
        self._deadline = None  # set by the first Bitcoin lookup of this run
        self._confirmed = {}   # block index -> (Bitcoin height, raw header or None, "saved" | "node" | "public")

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
            # Captured, like every other ots call: what it prints reaches the log
            # only as the one plain line a failure is reported with.
            r = subprocess.run(["ots", "stamp", str(p)], capture_output=True, text=True, errors="replace")
            if r.returncode != 0:
                said = (r.stderr + r.stdout).strip().splitlines()
                raise StampFailed(r.returncode, _plain(said[-1]) if said else "")
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

    @staticmethod
    def _node():
        """The Bitcoin node `ots` would use: the one $HOME/.bitcoin/bitcoin.conf names."""
        import bitcoin
        import bitcoin.rpc
        bitcoin.SelectParams("mainnet")
        return bitcoin.rpc.Proxy(timeout=_NODE_TIMEOUT)

    def verify(self, block: Block) -> tuple[str, str]:
        """(complete | pending | unchecked | failed, why), from the .ots itself.

        The proof is read, not run: its digest must be the SHA-256 of the block's own
        hash, and only an attestation that names a Bitcoin block is taken to a node.
        No `ots`, no calendar: moving a pending proof along is nightly's job.
        Whatever else breaks while checking a proof fails that proof, with a report
        line, instead of stopping verify with a traceback.
        """
        try:
            return self._check(block)
        except Exception as e:
            return "failed", f"the .ots could not be checked: {_plain(str(e)) or type(e).__name__}"

    def _check(self, block: Block) -> tuple[str, str]:
        try:
            from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation,
                                                    PendingAttestation, VerificationError)
            from opentimestamps.core.serialize import BytesDeserializationContext
            from opentimestamps.core.timestamp import DetachedTimestampFile
        except ImportError:
            return "unchecked", "python-opentimestamps is not installed here"

        p = self.ledger.proof_path(block.index, "hash.ots")
        if not os.path.lexists(p):
            return "pending", "no .ots proof yet"
        if p.is_symlink():
            return "failed", "the .ots is a link, never a proof"
        try:
            data = _read_regular(p, _OTS_MAX + 1)
        except OSError as e:
            return "failed", f"the .ots cannot be read: {_plain(str(e))}"
        if data is None:
            return "failed", "the .ots is not a regular file"
        if len(data) > _OTS_MAX:
            return "failed", "the .ots is far larger than any proof"
        try:
            proof = DetachedTimestampFile.deserialize(BytesDeserializationContext(data))
        except Exception as e:  # any way of not being a whole proof
            return "failed", f"the .ots is not a proof: {_plain(str(e)) or type(e).__name__}"
        # A proof attests its digest; how that digest was made from a file does not
        # matter, only that it is the SHA-256 of this block's hash.
        if proof.file_digest != hashlib.sha256(bytes.fromhex(block.hash)).digest():
            return "failed", "a proof of other data, not of this block"

        attested = sorted({(a.height, msg) for msg, a in proof.timestamp.all_attestations()
                           if isinstance(a, BitcoinBlockHeaderAttestation)})
        if len(attested) > _BITCOIN_BLOCKS_MAX:  # each would cost the node a request
            return "failed", "the .ots names more Bitcoin blocks than any proof does"
        if not attested:
            if any(isinstance(a, PendingAttestation) for _, a in proof.timestamp.all_attestations()):
                return "pending", "not yet in a Bitcoin block"
            return "failed", "no attestation that leads to Bitcoin"

        # A saved header (see save_header) is taken only if it carries this proof and
        # Bitcoin's proof of work; any other is ignored, and the block looked up.
        saved = self._saved_headers(block)
        for height, msg in attested:
            header = _from_saved(saved.get(height))
            if header is None:
                continue
            try:
                BitcoinBlockHeaderAttestation(height).verify_against_blockheader(msg, header)
            except VerificationError:
                continue
            self._confirmed[block.index] = (height, header.raw, "saved")
            return "complete", f"in Bitcoin block {height}, by its saved header"

        # One attestation Bitcoin confirms is enough. One it contradicts fails the
        # proof, whatever else could not be looked up; only when neither happens is
        # the proof unchecked. Either way nothing short of a confirmed block is complete.
        contradicted, unanswered = [], ""
        for height, msg in attested:
            try:
                header = self._header(height)
            except _Unanswered as e:
                # Heights go up, so a block not to be had leaves the rest unasked.
                unanswered = f"Bitcoin block {height} could not be looked up: {_plain(str(e))}"
                break
            try:
                BitcoinBlockHeaderAttestation(height).verify_against_blockheader(msg, header)
            except VerificationError:
                contradicted.append(height)
                continue
            raw = getattr(header, "raw", None)
            if raw is None and hasattr(header, "serialize"):  # python-bitcoinlib's, from the node
                raw = header.serialize()
            self._confirmed[block.index] = (height, raw, "public" if isinstance(self._node_state, str) else "node")
            return "complete", f"in Bitcoin block {height}"
        if contradicted:
            return "failed", f"Bitcoin block {contradicted[0]} does not carry it"
        return "unchecked", unanswered

    def save_header(self, block: Block) -> str:
        """Saves the header of the Bitcoin block that confirms this proof beside it, as
        <index>.btc-header, so later runs need no lookup: "saved", "already saved", or
        why not. Only once _SAVE_DEPTH blocks bury it (the block itself counted), by
        the same source's chain tip: a buried header never changes, a shallow one can
        still be replaced."""
        result, _ = self.verify(block)
        if result != "complete":
            return f"not saved: the proof is {result}"
        height, raw, source = self._confirmed[block.index]
        if source == "saved":
            return "already saved"
        if raw is None or len(raw) != 80:
            return "not saved: no header to save"
        if _from_saved(raw) is None:  # verify would never take it back from the file
            return "not saved: the header has less proof of work than Bitcoin's main chain"
        try:
            tip = self._tip(source)
        except Exception as e:  # out of time, or the tip not to be had
            return f"not saved: the chain's tip could not be had ({_kind(e) if source == 'public' else _plain(str(e))})"
        if tip - height + 1 < _SAVE_DEPTH:
            return f"not saved: Bitcoin block {height} has {max(tip - height + 1, 0)} confirmations, {_SAVE_DEPTH} needed"
        import tempfile
        p = self.ledger.proof_path(block.index, "btc-header")
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=p.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(f"{height} {raw.hex()}\n")
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp, 0o666 & ~umask)  # readable like the proofs; mkstemp makes 0600
            os.replace(tmp, p)  # replaces a link there, never writes through it
        except BaseException:
            if os.path.lexists(tmp):
                os.unlink(tmp)
            raise
        return "saved"

    def _tip(self, source: str) -> int:
        """The height of the chain's tip, as the source that confirmed the block sees it:
        the node, or the lower of the two public sources' tips."""
        if source == "node":
            node = self._node_state
            return int(self._within(node.getblockcount))
        tips = []
        for base in _PUBLIC_SOURCES:
            text = self._within(_fetch, f"{base}/blocks/tip/height")
            if not re.fullmatch(r"\d{1,8}", text):
                raise _BadReply("not a block height")
            tips.append(int(text))
        return min(tips)

    def _saved_headers(self, block: Block) -> dict:
        """{Bitcoin height: raw header} from the block's .btc-header, if that is a small
        regular file; a link, anything larger, or a line that is not one is ignored."""
        p = self.ledger.proof_path(block.index, "btc-header")
        try:
            if not os.path.lexists(p) or p.is_symlink():
                return {}
            data = _read_regular(p, _SAVED_MAX + 1)
        except OSError:
            return {}
        if data is None or len(data) > _SAVED_MAX:
            return {}
        out = {}
        for line in data.decode("ascii", "replace").splitlines():
            m = re.fullmatch(r"(\d{1,8}) ([0-9a-f]{160})", line)
            if m:
                out[int(m[1])] = bytes.fromhex(m[2])
        return out

    def _header(self, height: int):
        """Bitcoin block `height`'s header, looked up once per run; _Unanswered if not to be had."""
        if height not in self._headers:
            try:
                self._headers[height] = self._look_up(height)
            except _Unanswered as e:
                self._headers[height] = e
        got = self._headers[height]
        if isinstance(got, _Unanswered):
            raise got
        return got

    def _look_up(self, height: int):
        """From the node while it answers; else from both public sources, if they are on."""
        if self._node_state is None:
            try:
                self._node_state = self._node()
            except Exception as e:
                self._node_state = f"no Bitcoin node answered: {_plain(str(e))}"
        if not isinstance(self._node_state, str):
            node = self._node_state
            try:
                return self._within(lambda: node.getblockheader(node.getblockhash(height)))
            except _OutOfTime:
                raise
            except Exception as e:
                # Behind that block (IndexError), warming up, refused: not asked again this run.
                self._node_state = f"the Bitcoin node could not answer: {_plain(str(e))}"
        if not self.public:
            raise _Unanswered(self._node_state)
        return self._from_public(height)

    def _from_public(self, height: int):
        """The header both public sources give, if it hashes to the block they name and
        carries Bitcoin's proof of work. Neither source is trusted with anything else."""
        got = []
        for base in _PUBLIC_SOURCES:
            host = base.split("/")[2]
            try:
                block_hash = _hex(self._within(_fetch, f"{base}/block-height/{height}"), 32)
                raw = _hex(self._within(_fetch, f"{base}/block/{block_hash.hex()}/header"), 80)
            except _OutOfTime:
                raise
            except Exception as e:
                raise _Unanswered(f"{host}: {_kind(e)}; {self._node_state}")
            got.append((raw, block_hash))
        if len(set(got)) != 1:
            raise _Unanswered(f"the public sources do not agree on it; {self._node_state}")
        return _worked(*got[0])

    def _within(self, fn, *args):
        """fn(*args), unless the run's Bitcoin lookup budget runs out first. What is
        still running then is left behind, never waited for."""
        if self._deadline is None:
            self._deadline = time.monotonic() + _LOOKUP_BUDGET
        left = self._deadline - time.monotonic()
        box = {}

        def run():
            try:
                box["value"] = fn(*args)
            except BaseException as e:
                box["error"] = e
        if left > 0:
            t = threading.Thread(target=run, daemon=True)
            t.start()
            t.join(left)
        if not box:
            raise _OutOfTime(f"out of time: Bitcoin lookups get {_LOOKUP_BUDGET} s per verify run")
        if "error" in box:
            raise box["error"]
        return box["value"]


class _Unanswered(Exception):
    """A Bitcoin block's header was not to be had: the proof is not checked, never failed."""


class _OutOfTime(_Unanswered):
    pass


class _BadReply(OSError):
    """A public source's reply that is not what was asked for; the message is ours."""


def _kind(e: Exception) -> str:
    """What went wrong with a public source, in our words only: a source's own text
    (an HTTP reason phrase, say) could put a link into nightly's step summary."""
    import urllib.error
    if isinstance(e, _BadReply):
        return str(e)
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {int(e.code)}"
    return type(e).__name__


def _fetch(url: str) -> str:
    """One GET: the reply's text, if it is at most _REPLY_MAX bytes. Redirects are refused."""
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    request = urllib.request.Request(url, headers={"User-Agent": "aikiri-ledger"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=_LOOKUP_BUDGET) as r:
        body = r.read(_REPLY_MAX + 1)
    if len(body) > _REPLY_MAX:
        raise _BadReply("a reply longer than any header")
    return body.decode("ascii").strip()


def _hex(text: str, size: int) -> bytes:
    if not re.fullmatch(f"[0-9a-f]{{{2 * size}}}", text):
        raise _BadReply(f"not {size} bytes of hex")
    return bytes.fromhex(text)


def _target(bits: int) -> int:
    """The target a header's nBits encodes (Bitcoin's compact form); 0 if negative or empty."""
    exponent, mantissa = bits >> 24, bits & 0x007fffff
    if bits & 0x00800000 or not mantissa:
        return 0
    return mantissa << 8 * (exponent - 3) if exponent >= 3 else mantissa >> 8 * (3 - exponent)


def _worked(raw: bytes, block_hash: bytes):
    """The header in `raw`, if it hashes to `block_hash` (as shown, most significant byte
    first) and carries at least mainnet-scale proof of work; else _Unanswered."""
    h = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    if h[::-1] != block_hash:
        raise _Unanswered("a header that does not hash to the block it was given for")
    target = _target(int.from_bytes(raw[72:76], "little"))
    if target > _MAX_TARGET:
        raise _Unanswered("a header with less proof of work than Bitcoin's main chain")
    if int.from_bytes(h, "little") > target:
        raise _Unanswered("a header whose hash does not meet its own proof of work")
    return SimpleNamespace(hashMerkleRoot=raw[36:68], nTime=int.from_bytes(raw[68:72], "little"), raw=raw)


def _from_saved(raw: bytes | None):
    """A saved header, if it carries at least mainnet-scale proof of work; else None."""
    if raw is None:
        return None
    try:
        return _worked(raw, hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1])
    except _Unanswered:
        return None


_OTS_MAX = 64 << 10     # bytes; a proof is a few KB (4 calendars x 10,000 at most), and reading costs size squared
_NODE_TIMEOUT = 30      # seconds the node may stay silent; not a limit on a whole request
_BITCOIN_BLOCKS_MAX = 8  # a proof names one per calendar that completed it; ots uses four
_PUBLIC_SOURCES = ("https://mempool.space/api", "https://blockstream.info/api")
_LOOKUP_BUDGET = 60     # seconds for every Bitcoin lookup in one verify run, node and public
_REPLY_MAX = 1024       # bytes; a block hash is 64 hex characters, a header 160
_SAVED_MAX = 4096       # bytes of a saved .btc-header: save_header writes one 168-byte line
_SAVE_DEPTH = 6         # confirmations before a header is saved: the block and five on top
# Difficulty 5e13: half Bitcoin's average over blocks 856,760 to 886,157 (from Bitcoin
# Core 28 and 29's nMinimumChainWork). A header with this much work costs about half a
# block's mining to make; one with less is not taken from a public source or a saved file.
_MAX_TARGET = (0xffff << 208) // (5 * 10**13)


def _read_regular(p: Path, limit: int) -> bytes | None:
    """At most `limit` bytes of a regular file, never through a link; None if `p` is
    not a regular file. O_NONBLOCK so that a FIFO does not hang the open."""
    import stat
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, left = [], limit
        while left > 0:
            chunk = os.read(fd, min(left, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


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
            result, why = bitcoin.verify(b)
            report.append(f"block {b.index}: Bitcoin witness {'ok' if result == 'complete' else result}: {why}")
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

