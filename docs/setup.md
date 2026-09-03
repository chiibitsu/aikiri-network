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

The flow runs the other way, from her machine:

    # in the vault checkout, on her Mac
    aikiri-ledger request 03_human/journal/decision-journal.md --kind journal --out request.json
    aikiri-approve sign request.json
    # then push request.json to aikiri-network:ledger/requests/ on main

Only the hash travels. If a token is ever wanted for step three, it belongs in
the vault, scoped to this repository, and it can only ever add a request that
still needs her approval to become a block.

## 6. Publish the trust anchor

`trust.json` in this repository is a template, not an anchor: a verifier that
reads its expectations from the thing it is checking proves nothing, and the code
says so out loud — a trust file loaded from inside this worktree is labelled
`repo` and caps verification at `VALID LOCALLY`.

    aikiri-approve enroll --device mac
    aikiri-approve enroll --device iphone     # on the phone
    aikiri-ledger enroll --device mac --pubkey <hex> --out trust.json
    aikiri-ledger enroll --device iphone --pubkey <hex> --out trust.json

Then publish that file somewhere separate from this repository — the vault, a
gist, the artifact, her site — and verify against the published copy:

    aikiri-ledger verify --trust ~/aikiri-trust.json --rpc <a> --rpc <b> --rpc <c>

Until the devices are enrolled, `aikiri-ledger block` refuses to run. That is the
gate working, not a bug.
