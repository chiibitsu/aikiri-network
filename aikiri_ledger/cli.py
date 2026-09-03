"""aikiri-ledger.

  keygen                    create the validator key, outside any repository
  approve-keygen            create the approval key, encrypted with a passphrase
  approve <request>         approve a sealed request, passphrase required
  init                      write block 0
  enroll                    register an approval device in a trust file
  request <path>            vault side: the payload a device is asked to approve
  check-request <path>      verify a sealed request before it is pushed
  block                     write the block a sealed request approves
  witness <index>           anchor on Base, stamp on Bitcoin
  reconcile                 finish anchors whose receipt was never seen
  upgrade                   fetch completed Bitcoin proofs
  verify                    report one of four states
  deploy                    deploy the contract (once)

Keys come from the environment first, then from ~/.aikiri. Never from the repo.
  AIKIRI_VALIDATOR_KEY   ed25519 seed        fallback ~/.aikiri/chii.key
  BASE_PRIVATE_KEY       wallet key          fallback ~/.aikiri/base.env
Approval keys never leave the Secure Enclave of Chii's Mac and iPhone. Nothing
here can produce one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .approval import ApprovalKey, verify_approval
from .canonical import canonical_bytes, loads_strict
from .chain import (Ledger, VALIDATOR_KEY_ENV, key_from_env, load_key, new_key, save_key,
                    sha256_file)
from .errors import SchemaError, TrustError
from .request import Request, new_nonce, parse_roots
from . import softkey
from .trust import Trust
from .verify import State, verify_all
from .witness import (BASE_KEY_ENV, BaseWitness, BitcoinWitness, QuorumBase, base_key_from_env,
                      compile_contract, find_deployment, receipt_cost, wait_for_code)

DEFAULT_KEYFILE = os.path.expanduser("~/.aikiri/chii.key")
DEFAULT_BASE_ENV = os.path.expanduser("~/.aikiri/base.env")
IN_CI = bool(os.environ.get("CI"))
REQUIRE = {"local": State.VALID_LOCALLY, "base": State.BASE_VERIFIED,
           "full": State.FULLY_VERIFIED}


def _in_worktree(path: Path) -> bool:
    path = path.expanduser().resolve()
    here = Path.cwd().resolve()
    root = next((d for d in [here, *here.parents] if (d / ".git").exists()), None)
    return root is not None and (root in path.parents or path.parent == root)


def _cfg(ledger: Ledger) -> dict:
    p = ledger.root / "config.json"
    return loads_strict(p.read_text()) if p.exists() else {}


def _trust(args) -> Trust:
    path = getattr(args, "trust", None) or os.environ.get("AIKIRI_TRUST")
    if not path:
        return Trust.from_repo_defaults()
    return Trust.load(path)


def _validator_key(keyfile: str, create: bool = False):
    sk = key_from_env()
    if sk is not None:
        return sk, f"env {VALIDATOR_KEY_ENV}"
    kf = Path(keyfile)
    if kf.exists():
        return load_key(kf), str(kf)
    if not create:
        raise SystemExit(f"no validator key: set {VALIDATOR_KEY_ENV} or run `aikiri-ledger keygen`")
    if IN_CI:
        raise SystemExit(f"refusing to generate a validator key inside CI; set the "
                         f"{VALIDATOR_KEY_ENV} secret from a key made on your own machine")
    sk = new_key()
    save_key(sk, kf)
    print(f"new validator key written to {kf} (never commit this)")
    return sk, str(kf)


def _base_key() -> str:
    k = base_key_from_env()
    if k:
        return k
    p = Path(DEFAULT_BASE_ENV)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line.startswith(BASE_KEY_ENV + "="):
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                return v if v.startswith("0x") else "0x" + v
    raise SystemExit(f"no wallet key: set {BASE_KEY_ENV} or write it to {DEFAULT_BASE_ENV}")


def _w3(rpc: str, chain_id: int | None):
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(rpc))
    if chain_id is not None and w3.eth.chain_id != chain_id:
        raise SystemExit(f"rpc {rpc} is chainId {w3.eth.chain_id}, expected {chain_id}; refusing")
    return w3


def _base_reader(cfg: dict, trust: Trust, rpcs: list[str], need_signer: bool):
    contract = trust.contract or cfg.get("contract")
    urls = rpcs or ([cfg["rpc"]] if cfg.get("rpc") else [])
    if not contract or not urls:
        return None
    abi = compile_contract()["abi"]
    pk = _base_key() if need_signer else None
    readers = [BaseWitness(_w3(u, trust.chain_id or cfg.get("chainId")), contract, abi,
                           account=cfg.get("account"), private_key=pk) for u in urls]
    if need_signer or len(readers) == 1:
        return readers[0]
    return QuorumBase(readers)


def _requests(ledger: Ledger) -> list[Path]:
    return sorted(ledger.requests_dir.glob("*.json")) if ledger.requests_dir.exists() else []


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aikiri-ledger")
    ap.add_argument("--ledger", default="ledger")
    ap.add_argument("--trust", default=None, help="path to an external trust anchor")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ak = sub.add_parser("approve-keygen")
    ak.add_argument("--device", default="mac")
    ak.add_argument("--keyfile", default=None)
    ap_ = sub.add_parser("approve"); ap_.add_argument("path")
    ap_.add_argument("--device", default="mac"); ap_.add_argument("--keyfile", default=None)
    ap_.add_argument("--out", default=None)

    k = sub.add_parser("keygen"); k.add_argument("--keyfile", default=DEFAULT_KEYFILE)
    k.add_argument("--show", action="store_true", help="print the seed once, to paste into a secret")
    sub.add_parser("init").add_argument("--keyfile", default=DEFAULT_KEYFILE)

    e = sub.add_parser("enroll"); e.add_argument("--device", required=True)
    e.add_argument("--pubkey", required=True); e.add_argument("--out", default="trust.json")

    r = sub.add_parser("request"); r.add_argument("path")
    r.add_argument("--kind", default="journal"); r.add_argument("--out", default=None)
    sub.add_parser("check-request").add_argument("path")

    b = sub.add_parser("block"); b.add_argument("--keyfile", default=DEFAULT_KEYFILE)
    b.add_argument("--request", default=None)

    sub.add_parser("witness").add_argument("index", type=int)
    sub.add_parser("reconcile")
    sub.add_parser("upgrade")

    v = sub.add_parser("verify")
    v.add_argument("--rpc", action="append", default=[])
    v.add_argument("--offline", action="store_true", help="skip the witnesses entirely")
    v.add_argument("--require", choices=sorted(REQUIRE), default="full")

    d = sub.add_parser("deploy"); d.add_argument("--rpc", required=True)
    d.add_argument("--chain-id", type=int, default=8453)
    d.add_argument("--max-fee-eth", type=float, default=0.0005)
    d.add_argument("--adopt-only", action="store_true")

    a = ap.parse_args(argv)
    L = Ledger(a.ledger)

    if a.cmd == "keygen":
        kf = Path(a.keyfile).expanduser()
        if kf.exists():
            raise SystemExit(f"{kf} already exists; refusing to overwrite a validator key")
        if _in_worktree(kf):
            raise SystemExit(f"refusing to write a key inside a git worktree ({kf}). "
                             f"Keys live outside the repository, in ~/.aikiri.")
        sk = new_key(); save_key(sk, kf)
        print(f"validator key written to {kf} (never commit this)")
        print(f"validator (public): {sk.verify_key.encode().hex()}")
        if a.show:
            print(f"{VALIDATOR_KEY_ENV}={sk.encode().hex()}")
            print("that line is now in your shell history; clear it when you are done")
        return 0

    if a.cmd == "approve-keygen":
        import getpass
        kf = Path(a.keyfile) if a.keyfile else softkey.default_path(a.device)
        if _in_worktree(kf):
            raise SystemExit(f"refusing to write an approval key inside a git worktree ({kf})")
        if kf.exists():
            raise SystemExit(f"{kf} already exists; refusing to overwrite an approval key")
        pw = getpass.getpass("passphrase for the approval key: ")
        if pw != getpass.getpass("again: "):
            raise SystemExit("the two passphrases do not match")
        if len(pw) < 12:
            raise SystemExit("use at least 12 characters; this passphrase is the only thing "
                             "between the key file and someone who copies it")
        pub = softkey.create(kf, a.device, pw)
        print(f"approval key written to {kf} (never commit this, and back it up: "
              f"lose it and no further block can be approved)")
        print(f"device:  {a.device}")
        print(f"pubkey:  {pub}")
        print()
        print("Register it, then publish the trust file outside this repository:")
        print(f"  aikiri-ledger enroll --device {a.device} --pubkey {pub} --out trust.json")
        return 0

    if a.cmd == "approve":
        import getpass
        kf = Path(a.keyfile) if a.keyfile else softkey.default_path(a.device)
        if not kf.exists():
            raise SystemExit(f"no approval key at {kf}; run `aikiri-ledger approve-keygen`")
        payload = loads_strict(Path(a.path).read_text())
        try:
            roots = parse_roots(payload["roots"], "roots")
            index, prev_hash = payload["index"], payload["prev_hash"]
            nonce, validator = payload["nonce"], payload["validator"]
        except (KeyError, SchemaError) as e:
            raise SystemExit(f"{a.path} is not a request payload: {e}")

        # Show her what she is approving, before the passphrase.
        print(f"Approve block {index} of the Aikiri Network")
        print(f"  previous   {prev_hash}")
        print(f"  {roots[0]['kind']:<10} {roots[0]['sha256']}")
        print(f"  nonce      {nonce}")
        print(f"  validator  {validator}")
        print()
        approver = softkey.load(kf, getpass.getpass("passphrase: "))
        req = Request.build(index=index, prev_hash=prev_hash, roots=roots, nonce=nonce,
                            validator=validator, approver=approver)
        out = Path(a.out or a.path)
        out.write_text(req.to_json())
        print(f"approved by {approver.device}; sealed request written to {out}")
        return 0

    if a.cmd == "init":
        sk, source = _validator_key(a.keyfile, create=True)
        g = L.init(sk)
        print(f"genesis written: block 0 hash {g.hash}")
        print(f"validator (public): {g.validator}  [key from {source}]")
        return 0

    if a.cmd == "enroll":
        out = Path(a.out)
        trust = Trust.load(out) if out.exists() else Trust.from_repo_defaults()
        key = ApprovalKey(a.device, a.pubkey)
        trust.approval_keys = [k for k in trust.approval_keys if k.device != a.device] + [key]
        trust.source = "external-unsigned"
        trust.write(out)
        print(f"registered {a.device} in {out}")
        print(f"devices: {', '.join(k.device for k in trust.approval_keys)}")
        print("publish this file outside the repository; a copy kept beside the ledger "
              "is not an independent anchor")
        return 0

    if a.cmd == "request":
        trust = _trust(a)
        head = L.head()
        payload = Request.unsigned(index=head.index + 1, prev_hash=head.hash,
                                   roots=[{"kind": a.kind, "sha256": sha256_file(a.path)}],
                                   validator=trust.validator or L.head().validator,
                                   nonce=new_nonce())
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if a.out:
            Path(a.out).write_text(text)
            print(f"unsigned request for block {payload['index']} written to {a.out}")
            print("approve it on your Mac or iPhone: aikiri-approve sign " + a.out)
        else:
            sys.stdout.write(text)
        return 0

    if a.cmd == "check-request":
        trust = _trust(a)
        req = Request.parse(Path(a.path).read_text())
        ok, why = req.verify(trust.approval_keys or None)
        print(f"index {req.index}  prev {req.prev_hash[:16]}…  {req.roots[0]['kind']} "
              f"{req.roots[0]['sha256'][:16]}…")
        print(f"approval: {'ok, ' + req.approval['device'] if ok else 'REFUSED: ' + why}")
        return 0 if ok else 1

    if a.cmd == "block":
        trust = _trust(a)
        paths = [Path(a.request)] if a.request else _requests(L)
        if not paths:
            raise SystemExit(f"no sealed request in {L.requests_dir}/; a block is written only "
                             f"when Chii approves one on a registered device")
        if len(paths) > 1:
            raise SystemExit(f"{len(paths)} requests present; one block, one request. "
                             f"Leave exactly one: {', '.join(p.name for p in paths)}")
        req = Request.parse(paths[0].read_text())
        if not trust.approval_keys:
            raise SystemExit("no approval devices registered; run `aikiri-ledger enroll` and "
                             "supply the trust file with --trust")
        sk, _ = _validator_key(a.keyfile)
        blk = L.append_from_request(req, sk, registered=trust.approval_keys)
        print(f"block {blk.index} written: {blk.hash}")
        print(f"approved by {blk.approval['device']}")
        return 0

    if a.cmd == "witness":
        cfg = _cfg(L); trust = _trust(a)
        blk = L.read(a.index)
        base = _base_reader(cfg, trust, [], need_signer=True)
        if base:
            tx = L.anchor_with_marker(base, blk)
            print(f"Base: anchored block {blk.index} tx {tx}")
        else:
            print("Base: no rpc/contract configured; skipped")
        if BitcoinWitness.available():
            p = BitcoinWitness(L).stamp(blk)
            print(f"Bitcoin: stamped block {blk.index} -> {p.name} (pending until upgraded)")
        else:
            print("Bitcoin: `ots` not installed; `pip install opentimestamps-client`")
        return 0

    if a.cmd == "reconcile":
        cfg = _cfg(L); trust = _trust(a)
        base = _base_reader(cfg, trust, [], need_signer=True)
        if not base:
            print("no rpc/contract configured; nothing to reconcile")
            return 0
        done = L.reconcile(base)
        print(f"reconciled: {done}" if done else "nothing pending")
        return 0

    if a.cmd == "upgrade":
        bw = BitcoinWitness(L)
        for blk in L.blocks():
            if L.proof_path(blk.index, "hash.ots").exists():
                print(f"block {blk.index}: "
                      f"{'upgraded' if bw.upgrade(blk) else 'still pending'}")
        return 0

    if a.cmd == "verify":
        try:
            trust = _trust(a)
        except (TrustError, SchemaError) as e:
            print(f"trust anchor unusable: {e}")
            print(State.text(State.INVALID))
            return 1
        cfg = _cfg(L)
        base = btc = None
        if not a.offline:
            base = _base_reader(cfg, trust, a.rpc, need_signer=False)
            btc = BitcoinWitness(L) if BitcoinWitness.available() else None
        state, report = verify_all(L, trust, base=base, bitcoin=btc)
        print("\n".join(report))
        need = REQUIRE[a.require]
        if state < need:
            print(f"required at least {State.text(need)}")
            return 1
        return 0

    if a.cmd == "deploy":
        cfg_path = L.root / "config.json"
        if cfg_path.exists() and _cfg(L).get("contract"):
            raise SystemExit(f"{cfg_path} already names a contract; the ledger is deployed once")
        g = L.read(0)
        w3 = _w3(a.rpc, a.chain_id)
        c = compile_contract()
        bw = BaseWitness(w3, None, c["abi"], private_key=_base_key())
        print(f"deployer {bw.account} "
              f"(balance {w3.from_wei(w3.eth.get_balance(bw.account), 'ether')} ETH)")
        found = find_deployment(w3, bw.account, c["abi"], g.hash)
        if found:
            addr, rcpt = found
            print(f"adopting the AikiriLedger already deployed at {addr}; nothing sent")
            bw.contract = w3.eth.contract(address=addr, abi=c["abi"])
        elif a.adopt_only:
            raise SystemExit("--adopt-only: no matching deployment found; nothing sent")
        else:
            addr = bw.deploy(g.hash, c["bytecode"], max_fee_eth=a.max_fee_eth)
            rcpt = bw.last_receipt
            print(f"deployed at {addr} tx {rcpt['transactionHash'].hex()}")
        if rcpt is None:
            raise SystemExit(f"contract at {addr} found but its creation receipt was not")
        if not wait_for_code(w3, addr):
            raise SystemExit(f"no code visible at {addr}; re-run later, nothing is lost")
        cost = receipt_cost(rcpt)
        assert bw.matches(g) and bw.genesis_hash() == g.hash, "contract lacks the genesis hash"
        cfg_path.write_text(json.dumps({"rpc": a.rpc, "chainId": a.chain_id, "contract": addr,
                                        "account": bw.account}, indent=2) + "\n")
        (L.root / "deploy.json").write_text(json.dumps(
            {"contract": addr, "chainId": a.chain_id, "genesisHash": g.hash,
             "deployer": bw.account, "tx": rcpt["transactionHash"].hex(),
             "baseBlock": int(rcpt["blockNumber"]), "solc": "0.8.26",
             "optimizer": {"enabled": True, "runs": 200}, **cost}, indent=2) + "\n")
        print(f"wrote {cfg_path} and {L.root / 'deploy.json'}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
