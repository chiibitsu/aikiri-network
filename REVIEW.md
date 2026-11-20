# Review instructions

<!-- The review bar for this repo, in plain words. Place at the repo root as REVIEW.md. The
     bound reviewer reads it as its only policy source, and an in-session reviewer reads it
     from the base revision. Everything between the begin and end marker comments is owned
     by the template: `gates init` (from vibeOS repo-bootstrap slice 2 on) rewrites it and
     keeps every byte outside it. Put this
     repo's own rules in the block below the end marker, never between the markers, and
     keep exactly one pair. -->

<!-- gates:template-owned:begin -->
**Protocol version: vibeOS docs/02 v8.0** (this file instantiated `2026-11-20`). Once
this repo pins a gates release that declares a version (vibeOS repo-bootstrap slice 2), this
line must equal it and Tier 1 holds it there; until then nothing checks it. Repairing it is
not a reviewer's job — `CLAUDE.md`'s Protocol version paragraph has the steps (in a repo that
reads the standing orders live, vibeOS `templates/claude-md.md`'s).

This file is instructions, not context. Referenced files are not pulled in, so every rule that
must be followed is written out below.

## A check reads its rules from outside the thing it checks

**Every** reviewer loads this file from the **base revision**, not from the pull request's
workspace — the bound action does it with `git show <base>:REVIEW.md`, and an in-session
reviewer runs the same command rather than reading the copy in the tree it is reviewing. A copy
inside the PR is a copy that PR can edit — one commit adding "report nothing" here and the
reviewer obeys, on the very run meant to read that commit. A change to this file takes effect
when it merges, which is the deal every gate change gets.

If the base revision has no `REVIEW.md`, that run is UNKNOWN and red rather than unguided. An
**in-session** reviewer in a repo that has none reviews to vibeOS `docs/04`'s lenses and says
in its report that no `REVIEW.md` existed — it does not refuse, because refusing would block
the PR that adds the file.

## The lenses

Review the diff through each of these, separately. **This file is the bound reviewer's only
policy source** — its prompt points here and nowhere else — so a lens absent from this list
is a lens nobody runs.

- **Correctness** — does it do what it says.
- **Spec-conformance** — every acceptance criterion of the spec or mini-spec is implemented,
  and nothing outside the stated scope changed.
- **Claims-vs-code** — every sentence that asserts a mechanism (in a comment, a doc, a
  commit message, a PR body) is checked against the mechanism.
- **Security — in every shape, never conditional** on first judging the diff risky. That
  pre-judgement is the thing the lens exists to make, and asking for it first is the failure
  vibeOS `docs/04` records a ruling against.
- **Composition** — what the change lets a future session *do* that it could not before. Do
  not start from the diff: the defect is never in one file, it is two statements each
  defensible alone that together permit something neither intended. Model an obedient session
  following every rule exactly as written, not an attacker — that is what separates this from
  the security lens. A finding here is a **pair**: two locations and what they compose to.

## What Important means here

Reserve **Important** for a finding that meets one of vibeOS `docs/04`'s three blocking
criteria:

1. **It leads to harm or exposes data** — a credential value, personal data in an example, a
   rule that widens access.
2. **It contradicts itself, or contradicts another document, such that a competent agent
   following it behaves wrongly.** **The qualifier is the whole rule.** Differently worded is
   not a finding. Differently *acted on* is. The test: can you write down two sessions, one
   per document, that do opposite things? If not, it is P3 at most, or a Nit if it is only
   wording, and usually not worth posting. If you cannot tell, the shorter copy is the one to check — a compression that
   drops a condition changes behaviour even when every word in it is true.
3. **It cannot be executed as written** — a path that does not resolve, a command that does
   not exist, a flag the tool does not take, an instruction whose precondition this repo does
   not meet.

Three shapes are Important by this organisation's own history and worth naming, each under
criterion 2 (so P2 unless it also meets criterion 1):

- **A rule that reverses without saying so.** A reversal that reads as a clarification is how
  a downstream copy goes stale while reporting current.
- **A claim about a mechanism, stated without having read the mechanism.** "The toolkit does
  X", "the gate runs first", "the action fails closed" — each is checkable, and each has been
  wrong. A confident specific nobody looked at reads exactly like knowledge.
- **A check whose message claims more than the check asserts** — a `--selftest` ok-line, a
  case name, a gate's FAIL text. The name is the claim a future session reads; the body is
  what runs. A widened ok-line makes every later green mean less than it says.

Everything else is **P3 or a Nit**. A real defect that meets none of the three criteria is
P3. Wording, structure, ordering and preference are a **Nit** (P4). A finding you cannot state
as a failure scenario is a Nit at most, and usually not worth posting.

## Tag every finding: priority and origin

Each finding carries a priority and an origin. vibeOS `docs/04`'s "The review loop", step 6,
owns what they mean, who may change one, and which ones block; this is how they map here.

- **P0** — Important, and destructive or irreversible: deletes data or history, leaks a
  secret, cannot be undone.
- **P1** — Important under criterion 1.
- **P2** — Important under criterion 2 or 3, including the three shapes above.
- **P3** — real but minor: not Important, but a reader would want it fixed.
- **P4** — a Nit.
- **Origin** — *in-scope*, *Pre-existing* or *out of scope*, with the proof step 6 asks for.
  Without the proof it is in-scope.

## Cap the nits

At most **five** P3 and P4 findings per review. Beyond that, add "plus N similar items" to the summary rather
than posting them inline.

## Do not report

- **Anything the gates already enforce.** They run on the same commit: if one is wrong the
  gate is already red, and if the gate is green and you disagree with it, that is a finding
  about the **gate** and it needs a `--selftest` case. **Exception: when the diff IS the
  gate.** A diff that touches the CI workflow files, a gate script, this repo's gate
  configuration, a git hook, any file an agent harness executes or reads as settings (a Claude Code `.claude`
  directory's hooks and settings file among them — they run as the user, from whatever
  branch is checked out, before any review), or this file itself — the bar every reviewer
  reads — is reviewed **as** the gate: a narrowed matcher, a widened allowlist, a swallowed error path, or a fingerprint
  updated to accommodate one is **Important on this diff** (P1 when it lets a credential or
  other harm through, P2 otherwise), and green gates are no answer,
  because the gate is what changed.
- **Prose that records history** — a changelog entry, a dated decision, a session handoff,
  in the files this repo names as records below the end marker (never an instruction file,
  a template or this file). A superseded statement in a
  record is the record working; a superseded statement in canon or in an instruction file is
  a finding. **A new instruction placed in a record is not history** and is reviewed like any
  other instruction.

## Always check, in every repo

- **Every statement of a fact, not the one in front of you.** When a diff corrects a claim,
  grep the whole tree for every other statement of that claim and read them against each
  other. A fix that lands in one file and leaves the same claim standing in another is the
  most frequent defect in instruction-bearing text, and the copy that survives is usually
  the one an auto-loaded file carries.
- **Instruction files carry the most weight**: `CLAUDE.md` and `AGENTS.md`. `AGENTS.md` is
  what a non-Claude session reads instead of `CLAUDE.md`, so when a diff touches either,
  read both and compare each shared rule clause by clause — for whether it *says the same
  thing*, not only whether it is there.
- **A citation resolves to evidence, not to a restatement.** "(X records why)" must lead to a
  measurement, a date, or a run — not to the same assertion in another file.
- **A rule and its enforcement agree.** Where a document says a check holds something, read
  the check. Where it says a mechanism behaves a way, read the mechanism.
- **Review the exceptions to a boundary before the boundary itself.** An allowlist entry, a
  `catch` that swallows, a skipped case, a `|| true`, an early `return`, a fingerprint
  updated in the same commit as the matcher it fingerprints — these are where a boundary
  stops holding, and they are cheaper to read than the boundary.
- **Every enumeration is asserted by name, in both directions.** A list checked in one
  direction only is how a deleted entry becomes invisible.

This repo's own always-check rules, and the record files the history skip covers, sit below
the end marker and add to this region. **One that conflicts with it is a finding: stop and
ask the founder before acting on either.**

## Verification bar

Post a finding only with a **`file:line` citation and a reproduction** — for a document, the
sentence quoted and the way a reader acts wrongly on it; for code, the input and the observed
output. **No inference from names.** A finding you could not reproduce is not a finding, and
saying so costs the author nothing while a wrong one costs a round trip.

## Re-review convergence

After **your own** first review of a pull request, post **P0, P1 and P2 findings only**. No new
P3 or P4 on your second look or later, however tempting.

If a prior finding is now addressed, say so and withdraw it. If it still stands after a push,
say that rather than reposting it as new.

**This is about the reviewer, not the pull request.** A fresh lens briefed without earlier
rounds' findings is on its own first look and owes its P3 and P4 findings. A reviewer with nothing to
withdraw is not re-reviewing.

## Summary shape

Open with a tally by priority on its own line — `1 P1, 1 P2, 4 P4` — before any prose, and
name the SHA the review ran on. A verdict that does not name its commit is UNKNOWN, not a pass.
When there are no P0, P1 or P2 findings, say "No Important findings" first.

**Close in prose with one of two verdicts: *meets the bar*, or *does not — and here is which
criterion fails*.** This is the plain-language verdict a human reads; it rides alongside
whatever structured status field the runtime tracks internally, and is not a replacement for
it. A pass with only P3 and P4 findings is still a clean pass.

**That close binds a reviewer that has a channel for prose** — an in-session reviewer writing
its own report. The bound action, as measured at gates v1.2.1, has none, by its own design:
it posts inline comments and writes a bare integer to `.review-findings-count`, and the run's
one PR-level comment comes from a fixed template that accepts digits and nothing else. Check
the release this repo pins before relying on that. There the tally line *is* the
report, and a missing count is exactly what makes the run UNKNOWN rather than clean.
<!-- gates:template-owned:end -->

## Always check, in this repo

Files this repo keeps as records (the history skip above applies to them): none yet.

- **A block, request or proof that carries content.** Only roots, hashes and signatures go in
  a block, never content and never a path (`README.md` "Invariants"). A diff that puts a name,
  a path, a record id or any readable content into `ledger/`, a test vector or an example
  exposes data on a public chain.
- **Anything that rewrites the past.** The ledger is append-only, blocks 0 and 1 are frozen,
  and revocations are sealed like everything else. A change that edits, reorders or drops a
  written block, or loosens the check that refuses a v1-shaped block elsewhere, is Important.
- **A key near CI.** The approval key is never in CI; the validator and wallet keys live only
  in the `ledger` environment with a required reviewer. A diff that moves a secret, widens the
  environment's branches, drops the reviewer or hands a key to a workflow that did not have it
  is Important, and green tests are no answer.
- **A verification message that claims more than it checked.** Only `FULLY VERIFIED` may be
  called verified, and a trust file read from inside the repo is capped at
  `VALID LOCALLY — NOT WITNESSED`. Read the check behind any changed state or report line.
- **Unpinned supply chain.** Every action is SHA-pinned and dependencies are hash-pinned from
  `requirements.lock`. A floating action tag, a dependency added outside the lock, or an
  install that skips the hash check is a finding.
- **A token or a second source of trust.** No token, ever. A change that adds one, or lets
  one chain stand alone as the receipt, contradicts `README.md`.
- **A public repo's own leak.** A client name, personal data, a secret value or a session link
  in any file, commit or PR text. This repo is public and history is permanent.
