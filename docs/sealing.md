# Sealing a client's document

An app that issues documents to a client (today the Kreativ Dental Blueprint flow) seals each one on this ledger by its SHA-256. One record can have several documents: the accepted agreement, then the official invoice. Each gets its own block.

## The command

The app posts one line in Chii's chat per document. She pastes it on the sealing machine, in this checkout:

```
aikiri-ledger seal agreement <record id> <sha256>
aikiri-ledger seal invoice   <record id> <sha256>
aikiri-ledger seal-acceptance <record id> <sha256>    # the older line; the same as `seal agreement`
```

| argument | rule |
|---|---|
| document | `agreement` or `invoice` |
| record id | the app's id for the client record, 1 to 64 of `A-Z a-z 0-9 - _` |
| sha256 | 64 hex; a `0x` prefix and capitals are accepted and lowered |

Run it with `--push` (the line the app posts carries it):

1. It writes the unsigned request to `ledger/requests/next.json`, shows what you are approving, asks the device key's passphrase, commits that one file ("Request block N") and pushes it. It refuses if any other file is staged.
2. `block.yml` waits for your approval of the `ledger` environment in GitHub (Telegram says so), then writes the block, anchors it on Base, stamps it on Bitcoin, and **reports the seal to the app itself** (`report-block`, below).

That is the whole of it: one paste, one passphrase, one approval. Without `--push` the line only writes the request, as before: approve, commit and push it by hand, and once the block is written, `git pull` and run the line again to report it from the machine.

A repeat changes nothing. A request already waiting for the same document is left byte for byte. A sealed document gets no second request and no second block, and the app ignores a second report.

Refused, with nothing written:

- the same file already sealed or requested as the other document (one file is one document);
- another request already waiting (one block, one request; push it first);
- a malformed document, record id or hash.

## What goes on the ledger

A root, the same as every other block: `{"kind": "acceptance" | "invoice", "sha256": "<file hash>"}`. Nothing else. The record id never goes on the ledger: in the app it is the key to the client's own pages, and a public link between it and a fingerprint would say who the file belongs to. The two documents of one record are tied together by the app, which receives both reports with the same id, not by anything public.

| document | root kind |
|---|---|
| agreement | `acceptance` |
| invoice | `invoice` |

Adding a third document is one line in `DOCUMENTS` (`aikiri_ledger/seal.py`) and its kind in `ROOT_KINDS` (`aikiri_ledger/request.py`).

## The report to the app

### From block.yml, by fingerprint

After it commits a block, `block.yml` runs `aikiri-ledger report-block <index>`. For each root of kind `acceptance` or `invoice` it posts the report below **without `id`**: the ledger never holds the record id, so the app finds the record by the fingerprint. A block of any other kind reports nothing. The step runs even when verify is red, and a refused report turns the run red (`alerts.yml` tells you); the chat's line, run again, reports by hand.

| setting | where |
|---|---|
| `AIKIRI_SEAL_URL` | repository **variable** (Settings → Secrets and variables → Actions → Variables): the app's origin, `https://<app>` |
| `AIKIRI_SEAL_SECRET` | **secret of the `ledger` environment**: the app's `SEAL_SECRET` |

With either missing the step says "not reported" and stays green.

### From the sealing machine

Sent when the block holding the document has its Base receipt on disk (`ledger/proofs/NNNNNN.base.json`), and only if that receipt names the same block index and hash. Before that the command says so and sends nothing; a receipt of another block is refused.

```
POST https://<app>/api/seal
authorization: Bearer $AIKIRI_SEAL_SECRET
content-type: application/json

{"id": "<record id>",
 "document": "agreement" | "invoice",
 "sha256": "<the sealed file's hash>",
 "block": <block index>,
 "base_tx": "0x<64 hex>",
 "verify_url": "https://www.chiibitsu.com/network/check?sha=<sha256>",
 "ots_proof": "<base64 of ledger/proofs/NNNNNN.hash.ots>"}
```

`ots_proof` is sent only when the block's `.ots` is a regular file (never a link) that reads as a proof of this block, as `verify` reads it. It is left out otherwise: no `.ots` yet, not a proof, a proof of other data, or base64 over 50,000 characters (the app keeps no more, and a cut proof is no proof). The app keeps the first proof it is sent, so a wrong one would stay.

| setting | where |
|---|---|
| app origin | `--report https://<app>`, or `AIKIRI_SEAL_URL` in the environment. `https://host[:port]` only: no user, path, query or fragment. |
| bearer | `AIKIRI_SEAL_SECRET` in the environment. Never on the command line, never printed. |

With no app named the command prints the seal and sends nothing. A redirect is refused rather than followed, since following it would carry the bearer elsewhere. The command exits 0 on a 2xx answer, 1 otherwise.

`verify_url` uses the check page's `?sha=` link (from chiibitsu/chiibitsu-labs#34). Until that is live it opens empty and the visitor drops the file; the app accepts any link under `https://www.chiibitsu.com/network/`.

## Privacy

A fingerprint alone reveals nothing. The ledger holds the kind and the hash. The check page tells anyone *that* a file was sealed and *when*. Who it is between is answered by the document's issuer, and only to someone holding the original file. That protocol (a second digest the issuer stores at seal time) is the check page's: `chiibitsu/chiibitsu-labs:docs/network-check.md`, from [chiibitsu/chiibitsu-labs#34](https://github.com/chiibitsu/chiibitsu-labs/pull/34). The sealing machine has only the hash, so the issuer record is written by the app that holds the file.
