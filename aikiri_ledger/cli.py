"""aikiri-ledger CLI.

  keygen [--show]           create a validator key at ~/.aikiri/chii.key (outside repo)
  init                      write genesis (block 0) with the validator key
  seal <path> [--kind K]    queue a root for the next block (hash only)
  block                     build, sign, append today's block
  deploy --rpc URL          deploy AikiriLedger.sol with the genesis hash; write config.json
  witness <index>           anchor on Base (+ OTS stamp if `ots` installed)
  upgrade                   fetch completed OTS proofs
  verify                    chain -> signatures -> Base -> Bitcoin

Keys are read from the environment first, then from disk. Never from the repo.
  AIKIRI_VALIDATOR_KEY  ed25519 seed (64 hex)      fallback: ~/.aikiri/chii.key
  BASE_PRIVATE_KEY      wallet key (0x + 64 hex)   fallback: ~/.aikiri/base.env
Config: ledger/config.json {"rpc": ..., "chainId": 8453, "contract": "0x..", "account": "0x.."}. No keys in it.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .chain import Ledger, Root, new_key, save_key, load_key, sha256_file, key_from_env, VALIDATOR_KEY_ENV
from .witness import (BaseWitness, BitcoinWitness, compile_contract, verify_all, write_base_receipt,
                      base_key_from_env, receipt_cost, BASE_KEY_ENV)

DEFAULT_KEYFILE = os.path.expanduser("~/.aikiri/chii.key")
DEFAULT_BASE_ENV = os.path.expanduser("~/.aikiri/base.env")
IN_CI = bool(os.environ.get("CI"))


def _cfg(ledger: Ledger) -> dict:
    p = ledger.root / "config.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _validator_key(keyfile: str, create: bool = False):
    """Env first, then keyfile. `create` generates a keyfile locally when neither
    exists; in CI that is refused, because a key born in a runner dies with it."""
    sk = key_from_env()
    if sk is not None:
        return sk, f"env {VALIDATOR_KEY_ENV}"
    kf = Path(keyfile)
    if kf.exists():
        return load_key(kf), str(kf)
    if not create:
        raise SystemExit(f"no validator key: set {VALIDATOR_KEY_ENV} or run `aikiri-ledger keygen`")
    if IN_CI:
        raise SystemExit(f"refusing to generate a validator key inside CI; set the {VALIDATOR_KEY_ENV} secret "
                         f"(run `aikiri-ledger keygen --show` on your own machine and paste the hex)")
    sk = new_key(); save_key(sk, kf)
    print(f"new validator key written to {kf} (never commit this)")
    return sk, str(kf)


def _base_key() -> str:
    """Env first, then ~/.aikiri/base.env (a line BASE_PRIVATE_KEY=0x...)."""
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
    if chain_id is not None:
        got = w3.eth.chain_id
        if got != chain_id:
            raise SystemExit(f"rpc {rpc} is chainId {got}, config says {chain_id}; refusing")
    return w3


def _base(ledger: Ledger, cfg: dict, need_signer: bool) -> BaseWitness | None:
    if not cfg.get("rpc") or not cfg.get("contract"):
        return None
    w3 = _w3(cfg["rpc"], cfg.get("chainId"))
    pk = _base_key() if need_signer else None
    return BaseWitness(w3, cfg["contract"], compile_contract()["abi"], account=cfg.get("account"), private_key=pk)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aikiri-ledger")
    ap.add_argument("--ledger", default="ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--keyfile", default=DEFAULT_KEYFILE); k.add_argument("--show", action="store_true", help="print the seed hex once, for pasting into a secret")
    sub.add_parser("init").add_argument("--keyfile", default=DEFAULT_KEYFILE)
    s = sub.add_parser("seal"); s.add_argument("path"); s.add_argument("--kind", default="journal"); s.add_argument("--ref", default=None)
    sub.add_parser("block").add_argument("--keyfile", default=DEFAULT_KEYFILE)
    d = sub.add_parser("deploy"); d.add_argument("--rpc", required=True); d.add_argument("--chain-id", type=int, default=8453)
    d.add_argument("--max-fee-eth", type=float, default=0.0005, help="abort if worst-case deploy fee exceeds this")
    sub.add_parser("witness").add_argument("index", type=int)
    sub.add_parser("upgrade")
    sub.add_parser("verify")
    a = ap.parse_args(argv)

    L = Ledger(a.ledger)

    if a.cmd == "keygen":
        kf = Path(a.keyfile)
        if kf.exists():
            raise SystemExit(f"{kf} already exists; refusing to overwrite a validator key")
        sk = new_key(); save_key(sk, kf)
        print(f"validator key written to {kf} (never commit this)")
        print(f"validator (public): {sk.verify_key.encode().hex()}")
        if a.show:
            print(f"{VALIDATOR_KEY_ENV}={sk.encode().hex()}")
        return 0

    if a.cmd == "init":
        sk, source = _validator_key(a.keyfile, create=True)
        g = L.init(sk)
        print(f"genesis written: block 0 hash {g.hash}")
        print(f"validator (public): {g.validator}  [key from {source}]")
        return 0

    if a.cmd == "seal":
        h = sha256_file(a.path)
        L.seal(Root(kind=a.kind, sha256=h, ref=a.ref or str(a.path)))
        print(f"sealed {a.kind} {a.path} -> {h}")
        return 0

    if a.cmd == "block":
        sk, _ = _validator_key(a.keyfile)
        b = L.block(sk)
        print(f"block {b.index} written: hash {b.hash} ({len(b.roots)} roots)")
        return 0

    if a.cmd == "deploy":
        cfg_path = L.root / "config.json"
        if cfg_path.exists() and _cfg(L).get("contract"):
            raise SystemExit(f"{cfg_path} already names a contract; the ledger is deployed once")
        g = L.read(0)
        w3 = _w3(a.rpc, a.chain_id)
        c = compile_contract()
        bw = BaseWitness(w3, None, c["abi"], private_key=_base_key())
        bal = w3.from_wei(w3.eth.get_balance(bw.account), "ether")
        print(f"deploying from {bw.account} (balance {bal} ETH) on chainId {a.chain_id}")
        addr = bw.deploy(g.hash, c["bytecode"], max_fee_eth=a.max_fee_eth)
        rcpt = bw.last_receipt
        cost = receipt_cost(rcpt)
        assert bw.matches(g) and bw.genesis_hash() == g.hash, "contract does not carry the genesis hash"
        cfg = {"rpc": a.rpc, "chainId": a.chain_id, "contract": addr, "account": bw.account}
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
        deploy = {"contract": addr, "chainId": a.chain_id, "genesisHash": g.hash, "deployer": bw.account,
                  "tx": rcpt["transactionHash"].hex(), "baseBlock": int(rcpt["blockNumber"]),
                  "solc": "0.8.26", "optimizer": {"enabled": True, "runs": 200}, **cost}
        (L.root / "deploy.json").write_text(json.dumps(deploy, indent=2) + "\n")
        print(f"AikiriLedger at {addr}  tx {deploy['tx']}  Base block {deploy['baseBlock']}")
        print(f"fee: {w3.from_wei(cost['totalWei'], 'ether')} ETH (L2 {cost['l2FeeWei']} wei + L1 {cost['l1FeeWei']} wei)")
        print(f"wrote {cfg_path} and {L.root / 'deploy.json'}")
        return 0

    if a.cmd == "witness":
        cfg = _cfg(L); b = L.read(a.index)
        base = _base(L, cfg, need_signer=True)
        if base:
            tx = base.anchor(b)
            p = write_base_receipt(L, b, tx, cfg["contract"], cfg.get("chainId", 0))
            print(f"Base: anchored block {b.index} tx {tx} -> {p.name}")
        else:
            print("Base: no rpc/contract in config.json; skipped")
        if BitcoinWitness.available():
            p = BitcoinWitness(L).stamp(b)
            print(f"Bitcoin: stamped block {b.index} -> {p.name} (pending; run `upgrade` after ~1 Bitcoin block)")
        else:
            print("Bitcoin: `ots` not installed; `pip install opentimestamps-client`")
        return 0

    if a.cmd == "upgrade":
        bw = BitcoinWitness(L)
        for b in L.blocks():
            if (L.blocks_dir / f"{b.index:06d}.hash.ots").exists():
                print(f"block {b.index}: {'upgraded' if bw.upgrade(b) else 'still pending'}")
        return 0

    if a.cmd == "verify":
        cfg = _cfg(L)
        base = _base(L, cfg, need_signer=False)
        btc = BitcoinWitness(L) if BitcoinWitness.available() else None
        ok, report = verify_all(L, base=base, bitcoin=btc)
        print("\n".join(report))
        print("VERIFIED" if ok else "FAILED")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
