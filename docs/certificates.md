# Certificates: a cohort in one block

Chiibitsu Labs can seal a whole course cohort's certificates as **one block**. Anyone holding one certificate can later show that it was in that cohort, and whether it has been revoked: with this CLI, or in the browser from the public files under `ledger/certs/`.

A block holds exactly one root (`parse_roots`), and that rule stays. The cohort's root is the Merkle root of its certificates' fingerprints, sealed under the root kind `cert-cohort`. Each certificate gets its own small proof that leads from its fingerprint to that root.

## The issuer record and its fingerprint

The issuer record is what the certificate says. It is built and kept by the issuing app and lives with the holder, inside their own link. **A real record never enters this repository**: not in code, tests, docs, requests, blocks or the public files. This page fixes only its format; every value here and in the tests is fake.

### Fields

A JSON object with exactly these fields, and `host` only when the certificate names one:

| field | rule |
|---|---|
| `v` | `1` |
| `number` | the certificate number: **128 to 256 random bits** from a cryptographic random source, as 32 to 64 lowercase hex characters, never reused. It is the salt (below). |
| `holder` | who the certificate is for |
| `course` | the course |
| `completed` | the completion date exactly as printed on the certificate, `YYYY-MM-DD`, a real calendar date, no time and no time zone |
| `issuer` | who issues it. In format v1 it is exactly `Chiibitsu Labs`; any other value is refused, so no v1 record can read as valid otherwise. |
| `instructor` | who taught it |
| `host` | *optional.* Left out when the certificate names none; never present and empty. |

Every text field is 1 to 200 Unicode code points, NFC-normalised, with no control characters (U+0000–U+001F, U+007F) and no lone surrogates. No other field is accepted.

### Canonical bytes

JSON with the keys sorted (by code point), no whitespace, encoded as **UTF-8**. `v` is a bare integer; every other value is a string. There are no floats, NaN or Infinity. Inside a string only `"` and `\` are escaped, as `\"` and `\\`. Everything else is written as itself, in UTF-8, with no `\uXXXX` escapes: a non-ASCII character is its UTF-8 bytes, and 🎓 is the four bytes `f0 9f 8e 93`.

The record format already refuses control characters, lone surrogates and any string that is not NFC. Given that, these are exactly the bytes a browser's `JSON.stringify` gives for the same object with its keys in sorted order, encoded with `TextEncoder`.

**NFC.** Every string must already be NFC-normalised. The issuer normalises when it builds the record. A verifier does not normalise: it refuses a record or payload whose strings are not NFC. Silently normalising would give one certificate two encodings.

These bytes differ from the ledger's own canonical form (`canonical.py`, ASCII-escaped). That form is for what the ledger signs; this one is for what a browser has to rebuild.

### Fingerprint

```
fingerprint = SHA-256( "aikiri-ledger/cert-record/v1\n" || canonical bytes )
```

64 lowercase hex characters. It is the certificate's leaf in its cohort, and the name of its public files.

**Why the number matters.** Without a random number in the record, anyone who can guess what a record says (a name, a course, a date) could hash the guess and look for it in `ledger/certs/`. With 128 random bits in it, a fingerprint can't be guessed and says nothing to anyone who does not hold the record.

### The link payload

```
payload = base64url( canonical bytes )      RFC 4648 §5 alphabet, no "=" padding
```

The check page reads it from the link's fragment, `/network/cert#<payload>`, so it never reaches a server. A verifier **must** refuse a payload unless re-encoding the record it decodes to gives back exactly the same bytes, `canonical(parse(bytes)) = bytes`, and so the same payload. That leaves one valid payload per record. A payload with `=` padding, or with characters outside the base64url alphabet, is refused. A payload is at most 4,096 characters.

The payload carries the whole record, holder's name included. The holder controls who sees it: they choose whom to share the link with.

### Golden vectors

`tests/vectors/cert_cohort.json`, under `records`. Every value is fake except the issuer.

- Three records, each with its canonical bytes (as text and as hex), its fingerprint and its payload:
  - one plain;
  - one with `host`;
  - one with a non-ASCII holder name in NFC, a quote, a backslash, a dash and an emoji.
- A 1-, 2- and 3-leaf cohort of those fingerprints, each with its root and proofs, naming blocks 10, 11 and 12.
- A revoked fingerprint: its `revoked/` file, naming block 13.
- The sample blocks, with only the fields a reader takes from `ledger/blocks/` (index, timestamp, roots).
- The verdict each proof of the 3-leaf cohort must get against those blocks.

The check page's TypeScript tests against the same file.

## The fingerprint file

The input to `cohort build` and `cohort seal`: a text file, **one fingerprint per line**.

- 64 hex characters each. Capitals and a `0x` prefix are accepted and lowered.
- Lines are separated by `\n` (a `\r` before it is fine). Blank lines are skipped. Anything else is refused, and the message names the line: a comment, a comma, two fingerprints on a line, or any other separator.
- At least 1 and at most 65,536 fingerprints, all different. The same fingerprint twice is refused.
- Order does not matter: the leaves are sorted, so one set of certificates has exactly one root.

## The public files

Under `ledger/certs/`, on `main`, read by the check page from `raw.githubusercontent.com`. **Hashes only: never a name, a course or any other record field.** Each file is named by the salted fingerprint, so its name can't be guessed.

| file | holds |
|---|---|
| `ledger/certs/<fingerprint>.json` | the certificate's proof (format below) |
| `ledger/certs/revoked/<fingerprint>.json` | `{"block":<index>,"fingerprint":"<fingerprint>","v":1}`: the block that revokes it. The date is that block's timestamp. |

**These files are pointers, not evidence.** A file can be on `main` before its block is: the files are pushed with the request, and the block is written only after the approval in GitHub. A reader must check the block (`ledger/blocks/<index, six digits>.json`), as `cohort verify` does:

- **A proof** is good only if the block it names exists and its roots are exactly `[{"kind":"cert-cohort","sha256":<the proof's root>}]`: the one root of a v2 block. A proof with `"block": null`, or naming a block that isn't there or holds anything else, is **not found**.
- **A revoked file** counts only if the block it names exists and its roots are exactly `[{"kind":"revocation","sha256":<the fingerprint>}]`. Until then the certificate is still valid; the revocation is only requested.

Times shown to a reader come from block timestamps: when the cohort was sealed, and when it was revoked. The blocks carry them with a `+08:00` offset, and the page shows them in Asia/Manila. `completed` is a date and is shown exactly as written.

## The commands

All run from the `aikiri-network` checkout, like `seal`.

```
aikiri-ledger cohort build  <fingerprints.txt> --out <folder>       # preview: root + proofs, nothing requested
aikiri-ledger cohort seal   <fingerprints.txt> --push               # one paste, one passphrase, one approval
aikiri-ledger --trust ~/aikiri-trust.json cohort verify <proof.json | record.json | payload>
aikiri-ledger --trust ~/aikiri-trust.json cohort revoke <proof.json> --push
```

**build** computes the root and writes `<folder>/root.txt` and one `<folder>/<fingerprint>.json` per certificate, with `"block": null`. It touches no ledger and requests nothing: it shows the root before sealing. The folder must be outside the ledger and hold nothing but this cohort's files.

**seal** asks for the block, by the same request and approval path as `seal`. With `--push` it:

1. fast-forwards the checkout;
2. writes `ledger/requests/next.json` (kind `cert-cohort`, the root);
3. writes each proof to `ledger/certs/<fingerprint>.json`, naming the block the request is bound to;
4. shows what you are approving and asks the device key's passphrase;
5. commits the request and those proofs together, and pushes them.

`block.yml` runs on the request as for any block. It waits for your approval in GitHub, then writes, anchors and stamps the block. It does not touch `ledger/certs/`, so it needs no change. If the approval is never given, the proofs stay on `main` and read as not found.

A request is bound to one index. If another block lands first, the request can never be written. Running the line again then refuses it as stale, and writes no proof naming someone else's block. Delete it and run the line again.

A repeat changes nothing new. A request already waiting for the same root is kept (with `--push` it is approved if it was not yet, as with `seal`). Once the root is sealed, the line writes no request and leaves the proofs naming that block.

Refused, with nothing written:

- another request already waiting (one block, one request), or a stale one;
- the root already sealed as another kind;
- a certificate whose proof is already in `ledger/certs/` for another cohort (a certificate is in one cohort only);
- a bad fingerprint file;
- a link where a folder or proof should be.

**verify** takes one certificate as its proof file, its issuer record (a JSON file), or its link (the payload, or the whole URL). A record or payload is turned into its fingerprint and looked up in `ledger/certs/`. It prints the fingerprint, never the record, and one of:

| result | meaning | exit |
|---|---|---|
| `VALID` | the proof leads from this fingerprint to its root, the block it names seals exactly that root as `cert-cohort`, and no revocation block names the fingerprint | 0 |
| `REVOKED` | as VALID, and a `revocation` block names this fingerprint; the line says which block and when | 1 |
| `NOT FOUND` | the proof names no block (`null`); or its block is not on this ledger copy (not sealed yet, never approved, or the copy is behind: `git pull`); or its block seals something else; or a record or payload has no proof in `ledger/certs/` | 1 |
| `INVALID` | not a proof or a v1 record; a proof that does not lead to its root, or sits under another certificate's name; or this ledger copy itself does not verify | 1 |

It also prints the ledger's own state, checked offline (`VALID LOCALLY` or `INVALID`). Pass the external trust file as for `verify`. Without one, no approval key is registered, so every v2 block reads as unapproved and the result is `INVALID`. `aikiri-ledger verify` is what checks the Base and Bitcoin witnesses.

A revocation block counts wherever it sits on the ledger. Through `cohort revoke` it can only come after the cohort's block.

A record must also pass the format, issuer included: a record that names any issuer but `Chiibitsu Labs` is `INVALID`.

**revoke** seals one certificate's fingerprint under the existing `revocation` kind, as its own block, by the same request path. It writes `ledger/certs/revoked/<fingerprint>.json` naming that block, and `--push` commits the two together. It takes the certificate's proof, not a bare hash; with `--push` it pulls first. It refuses unless `verify` would say `VALID` on this ledger copy, so a typo cannot revoke anything. A certificate already revoked is left as it is.

## The Merkle tree

The construction is the **Merkle Tree Hash of RFC 9162** (Certificate Transparency v2, §2.1.1; the same as RFC 6962) and its audit path (§2.1.3). It differs from the RFC in one way: **the leaf and node prefixes are text, not the RFC's single bytes `0x00` / `0x01`**, in the style of every other hash on this ledger. A verifier must use these exact prefixes:

```
leaf(fp)   = SHA-256("aikiri-ledger/cert-leaf/v1\n" || fp)      fp: the fingerprint's 32 bytes
node(l, r) = SHA-256("aikiri-ledger/cert-node/v1\n" || l || r)
MTH([d])   = leaf(d)
MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n]))                       k: the largest power of 2 below n
```

- **Domain separation.** Leaves and nodes are hashed under different prefixes, so a leaf can never pose as a node, nor a node as a leaf.
- **Odd counts.** Nothing is padded or duplicated. The split at `k` leaves the right-hand subtree smaller, and the last leaf is carried up until it has a partner. The v1 `merkle_root` duplicated the odd leaf, which let `[a,b,c]` and `[a,b,c,c]` share a root. That cannot happen here.
- **Order.** The leaves are the fingerprints, sorted. The root does not depend on the order of the input file.
- **One certificate.** A cohort of one has an empty path; its root is `leaf(fp)`.

`aikiri_ledger/cohort.py` holds it. `tests/test_cohort.py` checks it against an independent RFC 9162 implementation, which itself reproduces the 8-entry test tree used across Certificate Transparency implementations.

## The proof

JSON, closed schema: these five fields, nothing else, no key twice. Written canonically (sorted keys, no whitespace), one file per certificate.

```json
{"block":7,"leaf":"<fingerprint>","path":[{"sha256":"<sibling>","side":"right"},{"sha256":"<sibling>","side":"left"}],"root":"<cohort root>","v":1}
```

| field | rule |
|---|---|
| `v` | `1` |
| `leaf` | the fingerprint, 64 lowercase hex |
| `root` | the cohort's root, 64 lowercase hex |
| `block` | the index of the block that seals the root, or `null` in a proof from `build` |
| `path` | from the leaf up, at most 16 steps. `side` is where the sibling sits: `left` means the next hash is `node(sibling, current)`; `right` means `node(current, sibling)`. |

Checking a proof needs no ledger and no network: hash the leaf, fold in each sibling on its side, and compare with `root`. That is `cohort.verify_proof`, a pure function. Matching the root to its block, and looking for revocations, is the ledger half of `cohort verify`.

## What is public, and what it says

- **The cohort block:** one root, `{"kind": "cert-cohort", "sha256": "<root>"}`.
- **A revocation block:** one root, `{"kind": "revocation", "sha256": "<fingerprint>"}`.
- **`ledger/certs/`:** one proof per certificate and one pointer per revocation, named by fingerprint.

From these, anyone can read a cohort's exact size, every fingerprint in it, which fingerprints were revoked, and when. A proof's path also gives its leaf's place in the sorted order. That is the whole of it. Each fingerprint hashes a record that carries 128 or more random bits, so without the record it names no one, and it can't be found by guessing what a record says. The link between a fingerprint and a person exists only in the record, which stays with the issuer and inside the holder's own link.

The files are pushed with the request, before the approval in GitHub. If a cohort is never approved, its proofs stay in the public history anyway, as hashes that no block ever seals.
