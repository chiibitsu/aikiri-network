# AGENTS.md — aikiri-network

<!-- gates:template-owned:begin -->
**Protocol version: vibeOS docs/02 v8.0** (this file instantiated `2026-11-20`). Once
this repo pins a gates release that declares a version (vibeOS repo-bootstrap slice 2), this
line must equal it and Tier 1 holds it there; until then the check is by hand.
`CLAUDE.md`'s Protocol version paragraph says how, and has the repair steps and the only two sources a gates SHA may
come from.

## Before you change anything: read `CLAUDE.md`

**This repo's standing orders are in `CLAUDE.md` at the repo root, and they bind every agent,
whichever harness it runs in.** The file is named for the harness that auto-loads it; nothing
in it is Claude-only. Read it in full before your first edit — the tier declaration, the
non-negotiables, the dates and specifics rules, and the rule on waiting are all there and
nowhere else.

**This file points rather than restates, deliberately.** A copy of a rule is a second place
for it to go wrong, and copies of these rules have drifted apart under review before: each
correction was right about what it fixed and wrong about something adjacent. The rules
below this region add to `CLAUDE.md`. **One that conflicts with it is a finding: stop and
ask the founder before acting on either.**

## Reviewing a change

**Read `REVIEW.md` first, from the base revision** (`git show <base>:REVIEW.md`), never from
the tree under review: a copy inside the PR is a copy that PR can edit. It carries the lenses,
the blocking criteria, the nit cap, the skip list, the verification bar and the verdict, and
for the bound reviewer it is the only policy source. **If the base has none, that command
exits 128** — review to vibeOS `docs/04` Tier 2's lenses and say in your report that no
`REVIEW.md` existed. Do not refuse, and do not fall back to the tree: refusing blocks the very
PR that adds the file.
<!-- gates:template-owned:end -->

## This repo

Nothing beyond `CLAUDE.md`, including its "Repo-specific gotchas".
