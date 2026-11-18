# Note for chiibitsu/kreativ-dental-US: seal the official invoice

From `aikiri-network`, 2026-10-19. The network side is built: `aikiri-ledger seal invoice <id> <sha256>`, contract in `docs/sealing.md`. This is what the app must change to use it. Nothing here edits that repo.

## 1. Post the seal line

When the official invoice is stored and fingerprinted (the same point Email 5 is sent), post once in the owner's chat:

```
seal invoice {id} {official_invoice_sha256}
```

Once only: tie it to the first file being stored, not to Email 5's retries. Optional: change the agreement line to `seal agreement {id} {pdf_sha256}`. `seal-acceptance {id} {pdf_sha256}` keeps working.

## 2. `POST /api/seal` takes a document

The body gains three fields (old callers send none of them):

| field | rule |
|---|---|
| `document` | `"agreement"` (default when absent) or `"invoice"`; anything else 400 |
| `sha256` | when present, must equal `pdf_sha256` (agreement) or `official_invoice_sha256` (invoice); otherwise 409 |
| `block` | the ledger block index; store it |

For `document: "invoice"`:

- 409 until `official_invoice_sha256` is set.
- Store `invoice_sealed_at`, `invoice_base_tx`, `invoice_ots_proof`, `invoice_verify_url`, `invoice_block`, written once (a transition conditional on `invoice_sealed_at` being null, as `sealAgreement` does with `sealed_at`).
- Same checks as today: bearer, `base_tx` is `0x` + 64 hex, `verify_url` under `https://www.chiibitsu.com/network/` or replaced by `NETWORK_CHECK`, proof capped at 50,000 characters.
- Do not send Email 4. Post "Invoice sealed · {client}".
- A repeat answers `{sealed: true, already: true}` and changes nothing.

The `agreement` path stays as `sealAgreement` is now, plus storing `block`.

## 3. Migration

Add to `blueprint_agreements`: `invoice_sealed_at timestamptz`, `invoice_base_tx text`, `invoice_ots_proof text`, `invoice_verify_url text`, `invoice_block integer`, and `seal_block integer` for the agreement.

## 4. Sealing machine settings

| variable | value |
|---|---|
| `AIKIRI_SEAL_URL` | the app's public origin, `https://<domain>` |
| `AIKIRI_SEAL_SECRET` | the same value as the app's `CRON_SECRET` |

With both set, the second run of the pasted line reports by itself. The `curl` in `docs/cta-flow.md` ("Running the seal") becomes a fallback.

## 5. Tests

- an invoice seal on a record whose agreement is already sealed stores the invoice fields and leaves the agreement's untouched;
- a repeat changes nothing and sends nothing;
- a `sha256` that is not the stored invoice hash is refused;
- an invoice seal before the invoice exists is refused;
- an old body (no `document`) still seals the agreement.

## 6. Docs

Replace the last sentence of "Official invoice (booklet)" in `docs/cta-flow.md` ("needs the network side … not built here") with the seal line and the report above.

## 7. Who the invoice is between (with chiibitsu/chiibitsu-labs#34)

The check page's private-by-default reveal ([chiibitsu/chiibitsu-labs#34](https://github.com/chiibitsu/chiibitsu-labs/pull/34), open, its store being connected) shows who a document is between only to someone holding the original file. The issuer stores that at seal time, and only the app holds the file bytes, so the app writes it. Once #34 is merged, when the invoice is stored (same point as step 1), `PUT https://www.chiibitsu.com/api/issuer/seal` with bearer `ISSUER_SEAL_SECRET`:

```
{"sha256": "<official_invoice_sha256>",
 "kind": "Official Invoice",
 "parties": ["Chiibitsu Labs", "<client legal name>"],
 "reveal": "<SHA-256 of the 17 bytes 'chiibitsu-reveal\n' followed by the file bytes>"}
```

and the same for the agreement with its own kind. One record per fingerprint, written once: a repeat with the same body answers 200, a different body 409. Until #34 is live the endpoint answers 404 (not merged) or 503 (store not set); treat either as "try again on the daily run", not a failure of the seal. The exact rules are in #34's `docs/network-check.md`; follow those, not this summary, if they differ.
