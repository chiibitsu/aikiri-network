# Aikiri Network ~ ledger

The Aikiri Network's own chain: the original source of truth for sealed outcomes, witnessed by Base (Chii's own contract) and Bitcoin (OpenTimestamps), and approved block by block from the Secure Enclave of her own devices. One validator for now. Members become validators later by signing each other's blocks.

Author: Angeline S. Viray. Working name only.

## Invariants

- Only roots, hashes, and signatures go in a block. Never content, and since v2 never a path either.
- A receipt never depends on a single chain to be believed.
- Nobody's accountability is on Chii's ledger. Every member stamps their own.
- Revocations are sealed like everything else.
- Append-only. Nothing is rewritten.
- No token, ever.

Several of these were aspirations rather than facts in v1. What closed the gap is in `docs/` and in the [security review](https://github.com/chiibitsu/aikiri-network/blob/main/docs/approval.md).

## Three factors, three holders

| factor | where it lives | what it alone can do |
|---|---|---|
| validator key | GitHub environment `ledger` | sign a block nobody approved: refused |
| wallet key | GitHub environment `ledger` | anchor a hash nobody approved: refused |
| approval key | passphrase-encrypted file on the Mac, outside the repo | nothing on its own |

A block needs all three. Holding the two automated keys is not consent, because the witnesses stamp whatever they are given: they prove time and order, never approval. See `docs/approval.md`.

## Layout

- `aikiri_ledger/canonical.py` ~ canonical bytes, domain separation, closed schemas
- `aikiri_ledger/chain.py` ~ block format, append-only store, sealed-request consumption
- `aikiri_ledger/approval.py` ~ P-256 approval from a registered device
- `aikiri_ledger/request.py` ~ the sealed request: one root, one nonce, consumed once
- `aikiri_ledger/trust.py` ~ where the verifier's expectations come from
- `aikiri_ledger/verify.py` ~ the four states
- `aikiri_ledger/witness.py` ~ Base contract, RPC quorum, Bitcoin via `ots`
- `contracts/AikiriLedger.sol` ~ owner-only anchor, sequential, no re-anchoring
- `ledger/` ~ `blocks/`, `proofs/`, `requests/`, `HEAD`, `config.json`, `deploy.json`
- `aikiri_ledger/softkey.py` ~ the approval key: P-256, passphrase-encrypted, never in CI
- `tools/approve/` ~ a Secure Enclave signer that macOS will not run as a CLI tool; see `docs/setup.md` §7
- `tests/vectors/` ~ golden bytes and hashes, checked on Linux and macOS across Python 3.11–3.13

## Block (v2, from block 2)

```json
{"v": 2, "index": 2, "timestamp": "2026-09-03T00:00:00+08:00", "prev_hash": "…",
 "roots": [{"kind": "journal", "sha256": "…"}], "nonce": "…",
 "approval": {"device": "mac", "pubkey": "04…", "sig": "30…"},
 "validator": "…", "signature": "…", "hash": "…"}
```

`hash = sha256("aikiri-ledger/block/v2\n" + canonical)`, where canonical is JSON with sorted keys, no whitespace, ASCII-escaped, no NaN, excluding `signature` and `hash`. The approval is inside the hashed bytes, so it cannot be stripped.

Blocks 0 and 1 predate this format. They are v1, they are anchored, their bytes are frozen, and they verify only against hashes pinned in an external trust anchor. A v1-shaped block anywhere else is refused.

## Verification has four states

```
INVALID
VALID LOCALLY — NOT WITNESSED
BASE VERIFIED — BITCOIN PENDING
FULLY VERIFIED
```

There is no grace window. A block that is written but not yet anchored leaves the ledger at `VALID LOCALLY`, which is the honest thing to say about it. Only the top state may be called verified.

```
aikiri-ledger verify --trust ~/aikiri-trust.json --rpc <a> --rpc <b> --rpc <c>
```

Several RPCs are read at a common finalized block. A majority must answer and they must agree; disagreement is never success. A trust file loaded from inside this repository is labelled `repo` and capped at `VALID LOCALLY`, because a verifier that reads its expectations from the thing it is checking proves nothing.

## Writing a block

```
# from the aikiri-network checkout ~ only the hash travels
aikiri-ledger request ../aikiri-garden/03_human/journal/decision-journal.md \
    --kind journal --out ledger/requests/next.json
aikiri-ledger approve ledger/requests/next.json        # passphrase
git add ledger/requests/next.json && git commit -m "Request block N" && git push
```

## Run

```
pip install -e ".[dev,bitcoin]"
python -m pytest -q
```

solc 0.8.26 is pinned by checksum. If the download is blocked, place `solc-static-linux` from the ethereum/solidity v0.8.26 release at `~/.solcx/solc-v0.8.26`; it must hash to `d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef`.

## Workflows

- `ci.yml` ~ tests on Linux and macOS, Python 3.11, 3.12, 3.13.
- `block.yml` ~ runs when a sealed request lands on `main`: write, anchor, stamp, commit, verify.
- `nightly.yml` ~ upgrade Bitcoin proofs and report the state. Writes no blocks.
- `deploy.yml`, `genesis.yml` ~ ran once each; both refuse to run again.

Every action is SHA-pinned, dependencies are hash-pinned, and the keys live in a GitHub environment with a required reviewer. Setup is in `docs/setup.md`.

## On chain

- Contract [`0x15eFF43a5CFA703215fAa943D42168aF5a7A6a9e`](https://basescan.org/address/0x15eff43a5cfa703215faa943d42168af5a7a6a9e) on Base (chainId 8453), source verified.
- Genesis `73715608c05be3f134036de0f5a1606b348098e2bebf34c8102680be08650ea8`.

## Not in v1

Members, witness ring, L3, acceptance links, legacy rules, key rotation, any UI beyond the CLI, any token.
