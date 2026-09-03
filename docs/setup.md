# Phase A ~ locking the runners

Settings, not code. None of it can be done from a pull request; all of it is in
GitHub's UI and on Chii's own machines.

## 1. Environments

Create two, under Settings → Environments.

**`ledger`** — holds the automated keys.
- Secrets: `AIKIRI_VALIDATOR_KEY`, `BASE_PRIVATE_KEY`.
- Required reviewers: Chii.
- Deployment branches: `main` only.

Used by `block`, `deploy`, `genesis`. The reviewer requirement is what stops a
pushed workflow change from spending the keys: editing a workflow no longer
grants access to what it runs with.

This is a second gate, separate from the device approval. The device approval
decides whether a block is legitimate; the environment reviewer decides whether
this runner may touch the keys at all. If one click per block turns out to be
one too many, the reviewer requirement is the one to drop, not the approval.

**`ledger-readonly`** — no secrets, no reviewers. Used by `nightly`, which now
only upgrades Bitcoin proofs and reports.

## 2. Move the secrets

Repository-level secrets are visible to every workflow on every branch. Delete
`AIKIRI_VALIDATOR_KEY` and `BASE_PRIVATE_KEY` from Settings → Secrets → Actions
and recreate them inside the `ledger` environment.

**`AIKIRI_GARDEN_TOKEN` must be deleted and not recreated.** The public repository
holds no vault credential. See §5.

## 3. Ruleset on `main`

Settings → Rules → New ruleset. Enforcement **Active**, target **Include default
branch**, bypass list **empty**, and exactly two rules:

- Restrict deletions.
- Block force pushes.

Nothing else. In particular **not** "Require a pull request before merging" and
**not** "Require status checks to pass", because both of them block the very
thing this repository exists to do.

The block workflow commits the block and its proofs straight to `main`. Under
either rule that push is rejected, and the usual escape — putting the pusher on
the bypass list — is not available here: the workflow pushes as
`github-actions[bot]`, and on a user-owned repository the bypass picker offers
only deploy keys, repository roles, and installed GitHub Apps. GitHub Actions is
not among them. So the choice is not "protect the branch or not"; it is "let the
ledger write or not".

The two rules that remain are the ones the invariant actually needs: history
cannot be rewritten and the branch cannot be deleted. CI still runs on every
push and still reports red or green; it is simply not a gate.

If the check names are ever wanted as a gate — when a second person arrives and
pull requests become real — the names are the matrix job names, six of them:
`test (ubuntu-latest, 3.11)` through `test (macos-latest, 3.13)`. There is no
check named `test` or `tests`; requiring one would block `main` forever.

## 4. What the workflows already enforce

Committed in code, and asserted by `test_workflows_are_locked` so it cannot
quietly regress:

- every action pinned to a commit SHA, not a tag;
- `pip install --require-hashes -r requirements.lock`, 43 packages, 1790 hashes;
- solc 0.8.26 checked against `d5f2343…f149ef`, the exact binary whose output
  Basescan verified;
- `push` triggers restricted to `main`;
- the request-file triggers removed;
- workflow inputs passed through `env:`, never interpolated into a shell line
  that also holds a key.

## 5. Trust direction

The public repository gets no credential to the vault. Nothing in a runner can
reach private content, even if the runner is fully compromised.

The flow runs the other way, from her machine. Run it from the **aikiri-network**
checkout, not the vault: building a request needs the chain's head (its index and
prev_hash), which lives in `ledger/`. The vault path is just an argument, and only
its hash is read.

    cd ~/aikiri-network
    aikiri-ledger request ../aikiri-garden/03_human/journal/decision-journal.md \
        --kind journal --out ledger/requests/next.json
    aikiri-approve sign ledger/requests/next.json
    git add ledger/requests/next.json && git commit -m "Request block N" && git push

That push is what starts the block workflow. Only the hash travels; the journal
itself never leaves the vault. If a token is ever wanted so the vault can push the
request itself, it belongs in the vault, scoped to this repository, and it can only
ever add a request that still needs her approval to become a block.

## 6. Publish the trust anchor

`trust.json` in this repository is a template, not an anchor: a verifier that
reads its expectations from the thing it is checking proves nothing, and the code
says so out loud — a trust file loaded from inside this worktree is labelled
`repo` and caps verification at `VALID LOCALLY`.

    # on the Mac
    swiftc -O -framework Security -framework LocalAuthentication \
        -o aikiri-approve tools/approve/AikiriApprove.swift
    ./aikiri-approve enroll --device mac
    aikiri-ledger enroll --device mac --pubkey <hex> --out trust.json

**The iPhone cannot be enrolled yet.** See §7.

Then publish that file somewhere separate from this repository — the vault, a
gist, the artifact, her site — and verify against the published copy:

    aikiri-ledger verify --trust ~/aikiri-trust.json --rpc <a> --rpc <b> --rpc <c>

Until the devices are enrolled, `aikiri-ledger block` refuses to run. That is the
gate working, not a bug.

## 7. The iPhone is not done

Chii's ruling was two devices registered from the start, so that losing one does
not stop the chain. What is shipped is a macOS command-line signer. There is no
iOS app, so today only the Mac can hold an approval key, and the Mac is a single
point of failure: lose it and the chain freezes.

The verifier already handles two devices; nothing in the format or the trust
anchor needs to change. What is missing is a way to create and use an enclave key
on the phone. Three routes, in order of how much they cost:

1. **A second Mac or MacBook.** Enroll it as `mac2` with the tool that already
   exists. No new code, works today. It is not the phone, but it is a genuinely
   separate device with a separate failure mode, which is the property that
   matters.
2. **A small iOS app**, built in Xcode and run on the phone. This is the ruling as
   written. Two things need checking before relying on it, and neither can be
   checked from here: whether a free personal provisioning profile is enough
   (those apps expire after seven days and must be re-run from Xcode), and whether
   deleting or re-installing the app destroys the enclave key with it. If it does,
   the phone key is fragile in exactly the way a recovery factor must not be.
3. **Wait**, and run on the Mac alone until rotation exists. Honest, and the worst
   of the three: it is the single point of failure described above.

Route 1 today, route 2 when there is time to verify it properly, is the
recommendation. Either way this is Chii's call, not an implementation detail.
