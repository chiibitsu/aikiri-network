# Aikiri Network ~ ledger

The Aikiri Network's own chain: the original source of truth for sealed outcomes, witnessed by Base (Chii's own contract) and Bitcoin (OpenTimestamps). One validator for now. Members become validators later by signing each other's blocks.

Author: Angeline S. Viray. Working name only.

## Invariants
- Only roots, hashes, and signatures go in a block. Never content. Chain data is public forever.
- A receipt never depends on a single chain to be believed.
- Nobody's accountability is on Chii's ledger. Every member stamps their own.
- Revocations are sealed like everything else.
- Append-only. Nothing is rewritten.
- No token, ever.

## Layout
- `aikiri_ledger/chain.py` ~ block format, canonical hashing, ed25519 signing, Merkle root, append-only store, chain verify
- `aikiri_ledger/witness.py` ~ Base witness (contract via web3, local signing), Bitcoin witness (`ots` wrapper), full verifier
- `aikiri_ledger/cli.py` ~ `keygen | init | seal | block | deploy | witness | upgrade | verify`
- `contracts/AikiriLedger.sol` ~ owner-only anchor contract, sequential, no re-anchoring, free `matches()` for anyone
- `ledger/` ~ the chain: `blocks/000000.json`, …, `HEAD`, `config.json` (rpc, chainId, contract, account; no keys), proofs beside blocks
- `tests/` ~ the contract runs on an in-process EVM
- `demo.py` ~ full ritual plus a backdating attack the chain alone accepts and the Base witness catches

## Block (v1)
```json
{"index": 1, "timestamp": "…+08:00", "prev_hash": "…", "roots": [{"kind": "journal", "ref": "…", "sha256": "…"}],
 "merkle_root": "…", "validator": "<ed25519 pubkey hex>", "signature": "<ed25519 over hash>", "hash": "<sha256 of canonical bytes>"}
```
Canonical bytes: JSON, sorted keys, no whitespace, UTF-8, excluding `signature` and `hash`. Chain valid iff every `prev_hash` matches the previous `hash` and every signature verifies.

## Keys
Never in the repo. Read from the environment first, then from disk outside the repo.
- `AIKIRI_VALIDATOR_KEY` ~ ed25519 seed, 64 hex. Local fallback `~/.aikiri/chii.key`.
- `BASE_PRIVATE_KEY` ~ wallet key, `0x` + 64 hex. Local fallback `~/.aikiri/base.env` (one line `BASE_PRIVATE_KEY=0x…`).

In GitHub Actions both live as repository secrets. `init` refuses to generate a key inside CI, because a key born in a runner dies with it.

## Run
```
pip install -e ".[dev,bitcoin]"
python -m pytest -q
aikiri-ledger init                      # block 0
aikiri-ledger deploy --rpc https://mainnet.base.org   # once; writes ledger/config.json
aikiri-ledger seal <path> --kind journal
aikiri-ledger block
aikiri-ledger witness <index>           # Base anchor + OTS stamp (pending)
aikiri-ledger upgrade                   # next day: completed OTS proofs
aikiri-ledger verify                    # anyone, with only ledger/ and network access
```
solc 0.8.26 is fetched by py-solc-x. If that download is blocked, place `solc-static-linux` from the ethereum/solidity v0.8.26 release at `~/.solcx/solc-v0.8.26`.

## Workflows
- `ci.yml` ~ tests on every push.
- `genesis.yml` ~ once: `init`, commit block 0. That commit is the network's genesis.
- `deploy.yml` ~ once: deploy the contract to Base with the genesis hash, commit `config.json` and `deploy.json`. If the wallet already deployed it, adopt it; never deploy twice.
- `block.yml` ~ when a hash-only `ledger/queue.json` is pushed: sign the next block, anchor on Base, stamp on Bitcoin, commit block + proofs, verify.
- `nightly.yml` ~ Manila midnight: upgrade yesterday's Bitcoin proofs, seal the vault's decision journal (hash only, vault checked out outside the repo), block, witness, commit. Needs the `AIKIRI_GARDEN_TOKEN` secret (read access to the vault).

Secrets: `AIKIRI_VALIDATOR_KEY`, `BASE_PRIVATE_KEY`, `AIKIRI_GARDEN_TOKEN`. Never in the repo.

## On chain
- Contract: `0x15eFF43a5CFA703215fAa943D42168aF5a7A6a9e` on Base (chainId 8453). See `ledger/deploy.json`.
- Genesis: block 0, hash `73715608c05be3f134036de0f5a1606b348098e2bebf34c8102680be08650ea8`.

## Not in v1
Members, witness ring, L3, scenario schema beyond a hash, acceptance links, legacy rules, any UI beyond the CLI, any token.
