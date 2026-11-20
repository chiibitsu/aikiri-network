# Certificates: a cohort in one block

Chiibitsu Labs can seal a whole course cohort's certificates as **one block**, and anyone holding one certificate's proof can later show that it was in that cohort, and whether it has been revoked.

A block holds exactly one root (`parse_roots`), and that rule stays. The cohort's root is the Merkle root of its certificates' fingerprints, sealed under the root kind `cert-cohort`. Each certificate gets its own small proof file that leads from its fingerprint to that root.

## The fingerprint: the input contract

This repository never sees a certificate. It sees only **fingerprints**: one 64-hex SHA-256 per certificate.

```
fingerprint = SHA-256( canonical issuer record )
```

The issuer record is built, stored and canonicalised by the issuing app (story 2), and **never enters this repository**: not in code, tests, docs, requests or blocks. What this side requires of it:

| rule | why |
|---|---|
| The record includes a **random certificate number of at least 128 bits**, from a cryptographic random source, never reused. | It is the salt. Without it, anyone who can guess what a record says (a name, a course, a date) could hash the guess and find it on the public ledger. With it, a fingerprint says nothing to anyone who does not hold the record. |
| The record's bytes are canonical: the same record always gives the same bytes. | So the issuer can recompute a fingerprint and match it to its proof. The encoding is the issuer's to define. |
| One certificate, one fingerprint. A reissued certificate gets a new certificate number, so a new fingerprint. | Two certificates with one fingerprint are refused (see below), and a revocation names exactly one certificate. |

### The fingerprint file

The input to `cohort build` and `cohort seal`: a text file, **one fingerprint per line**.

- 64 hex characters each. Capitals and a `0x` prefix are accepted and lowered.
- Blank lines are skipped. Anything else (a comment, a comma, two on a line) is refused, naming the line.
- At least 1 and at most 65,536 fingerprints, all different. The same fingerprint twice is refused.
- Order does not matter: the leaves are sorted, so one set of certificates has exactly one root.

## The commands

All run from the `aikiri-network` checkout, like `seal`.

```
aikiri-ledger cohort build  <fingerprints.txt> --out <folder>          # root + proofs, nothing requested
aikiri-ledger cohort seal   <fingerprints.txt> --out <folder> --push   # one paste, one passphrase, one approval
aikiri-ledger --trust ~/aikiri-trust.json cohort verify <proof.json>
aikiri-ledger cohort revoke <proof.json> --push
```

**build** computes the root and writes `<folder>/root.txt` and one `<folder>/<fingerprint>.json` per certificate, with `"block": null`. It touches no ledger and requests nothing: use it to see the root before sealing.

**seal** does what `build` does, and asks for the block. It is the same request and approval path as `seal`: with `--push` it fast-forwards the checkout, writes `ledger/requests/next.json` (kind `cert-cohort`, the root), shows what you are approving, asks the device key's passphrase, commits that one file and pushes it. `block.yml` then waits for your approval in GitHub and writes, anchors and stamps the block. The proofs name the block the request is bound to (a request is bound to one index; if another block lands first it is refused, never moved).

A repeat changes nothing: a request already waiting for the same root is left byte for byte, and once the root is sealed the line writes no request and rewrites the proofs with that block's index. Refused, with nothing written: another request already waiting (one block, one request); the root already sealed as another kind; a bad fingerprint file; a proofs folder holding anything other than this cohort's `root.txt` and proofs.

Write the proofs folder **outside this repository**. The proofs hold only hashes, but they belong with the issuer's records, not in a public repo.

**verify** checks one proof and prints one of:

| result | meaning | exit |
|---|---|---|
| `VALID` | the proof leads from this fingerprint to a root that a `cert-cohort` block on this ledger seals, and no revocation names it | 0 |
| `REVOKED` | as VALID, and a `revocation` block names this fingerprint; the line says which block | 1 |
| `NOT SEALED` | the proof is sound, but no `cert-cohort` block on this ledger copy seals its root (not sealed yet, or the copy is behind: `git pull`) | 1 |
| `INVALID` | the proof does not lead to its root, names a different block than the one that seals its root, or this ledger copy itself does not verify | 1 |

It also prints the ledger's own state, checked offline (`VALID LOCALLY`, or `INVALID`). Pass the external trust file as for `verify`: without one, no approval key is registered and every v2 block reads as unapproved. `aikiri-ledger verify` is what checks the Base and Bitcoin witnesses.

A revocation counts wherever it sits on the ledger. Through `cohort revoke` it can only come after the cohort's block.

**revoke** seals one certificate's fingerprint under the existing `revocation` kind, as its own block, by the same request path. It takes the certificate's proof, not a bare hash, and refuses unless `verify` would say `VALID` against this ledger, so a typo cannot revoke anything. A certificate already revoked is left as it is.

## The Merkle tree

The construction is the **Merkle Tree Hash of RFC 9162** (Certificate Transparency v2, §2.1.1) and its audit path (§2.1.3), with text domain prefixes in place of the RFC's single `0x00` / `0x01` bytes, in the style of every other hash on this ledger:

```
leaf(fp)   = SHA-256("aikiri-ledger/cert-leaf/v1\n" || fp)      fp: the fingerprint's 32 bytes
node(l, r) = SHA-256("aikiri-ledger/cert-node/v1\n" || l || r)
MTH([d])   = leaf(d)
MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n]))                       k: the largest power of 2 below n
```

- **Domain separation.** Leaves and nodes are hashed under different prefixes, so a leaf can never pose as a node, nor a node as a leaf.
- **Odd counts.** Nothing is padded or duplicated. The split at `k` leaves the right-hand subtree smaller, and the last leaf is carried up until it has a partner. (The v1 `merkle_root` duplicated the odd leaf, which let `[a,b,c]` and `[a,b,c,c]` share a root. That cannot happen here.)
- **Order.** The leaves are the fingerprints sorted, so the root does not depend on the order of the input file.
- **One certificate.** A cohort of one has an empty path; its root is `leaf(fp)`.

`aikiri_ledger/cohort.py` holds it. `tests/test_cohort.py` checks it against an independent RFC 9162 implementation, which itself reproduces the 8-entry test tree used across Certificate Transparency implementations. The golden vectors are in `tests/vectors/cert_cohort.json`.

## The proof

JSON, closed schema: these five fields, nothing else. Written canonically (sorted keys, no whitespace), one file per certificate.

```json
{"v": 1,
 "leaf": "<the certificate's fingerprint>",
 "root": "<the cohort's root>",
 "block": 7,
 "path": [{"side": "right", "sha256": "<sibling>"},
          {"side": "left",  "sha256": "<sibling>"}]}
```

| field | rule |
|---|---|
| `v` | `1` |
| `leaf` | the fingerprint, 64 lowercase hex |
| `root` | the cohort's root, 64 lowercase hex |
| `block` | the index of the block that seals the root, or `null` in a proof from `build` |
| `path` | from the leaf up, at most 16 steps. `side` is where the sibling sits: `left` means the next hash is `node(sibling, current)`, `right` means `node(current, sibling)` |

Checking a proof needs no ledger and no network: hash the leaf, fold in each sibling on its side, compare with `root`. That is `cohort.verify_proof`, a pure function. Matching the root to a block, and looking for revocations, is `verify`'s ledger half.

## What goes on the ledger

The cohort block: one root, `{"kind": "cert-cohort", "sha256": "<root>"}`. Not the fingerprints, not their number, nothing about the course.

A revocation block: one root, `{"kind": "revocation", "sha256": "<fingerprint>"}`. That fingerprint becomes public, which is the point (anyone can check it), and it is safe because of the salt: without the issuer record it names no one.

A proof's path length tells its holder roughly how large the cohort was (a cohort of n has paths of about log2 n steps). Nothing else about the other certificates can be read from it.

`block.yml` needs no change: a `cert-cohort` block is written, anchored and stamped like any other, and `report-block` reports nothing for it (it reports only client documents, `docs/sealing.md`).
