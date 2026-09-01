"""End-to-end run against an in-process Base (EthereumTesterProvider).
Same code path as production; only the RPC differs.
Expects a file `decision-journal.md` beside this script (any content ~ only its hash is used)."""
import json, tempfile, os
from pathlib import Path
from datetime import datetime
from web3 import Web3, EthereumTesterProvider
from aikiri_ledger.chain import Ledger, Root, new_key, sha256_file, MANILA
from aikiri_ledger.witness import compile_contract, BaseWitness, verify_all, write_base_receipt

work = Path(tempfile.mkdtemp())
L = Ledger(work / "ledger")
sk = new_key()

# 1. genesis
g = L.init(sk, now=datetime(2026, 9, 2, 2, 32, tzinfo=MANILA))
print("block 0 (genesis)   ", g.hash)

# 2. Base: deploy Chii's contract with the genesis hash baked in
w3 = Web3(EthereumTesterProvider()); chii = w3.eth.accounts[0]
c = compile_contract()
base = BaseWitness(w3, None, c["abi"], account=chii)
addr = base.deploy(g.hash, c["bytecode"])
print("AikiriLedger.sol at ", addr)

# 3. seal the decision journal (hash only ~ content never leaves the vault)
journal = Path("decision-journal.md")
L.seal(Root(kind="journal", sha256=sha256_file(journal), ref="03_human/journal/decision-journal.md"))
b1 = L.block(sk, now=datetime(2026, 9, 2, 23, 59, tzinfo=MANILA))
print("block 1 (journal)   ", b1.hash, "| journal sha256", b1.roots[0]["sha256"][:16] + "...")

# 4. witness on Base
tx = base.anchor(b1)
write_base_receipt(L, b1, tx, addr, 8453)
print("Base anchor tx      ", tx)

# 5. verify: chain -> signatures -> Base
ok, report = verify_all(L, base=base)
print("\n".join("  " + r for r in report)); print("VERIFIED" if ok else "FAILED")

# 6. attack: rewrite block 1 with a re-signed backdated copy
from aikiri_ledger.chain import Block
d = json.loads((L.blocks_dir / "000001.json").read_text()); d["timestamp"] = "2019-06-15T00:00:00+08:00"
forged = Block(**{k: d[k] for k in Block.__dataclass_fields__}).sign(sk)
(L.blocks_dir / "000001.json").write_text(forged.to_json()); L.head_path.write_text(f"1 {forged.hash}\n")
ok, report = verify_all(L, base=base)
print("\nafter backdating block 1 on the local copy:")
print("\n".join("  " + r for r in report)); print("VERIFIED" if ok else "FAILED (witness caught it)")
print("\nfiles:", sorted(p.name for p in L.blocks_dir.iterdir()))
