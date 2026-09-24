"""Verification, in four states.

  INVALID                            something is wrong; the report says what
  VALID LOCALLY — NOT WITNESSED      the chain is internally sound, nothing more
  BASE VERIFIED — BITCOIN PENDING    a stranger's chain agrees, Bitcoin has not settled
                                     or could not be checked here (no Bitcoin node, or
                                     ots crashing inside its calendar client)
  FULLY VERIFIED                     both witnesses agree

There is no grace window and no partial credit. A block that is written but
not yet anchored leaves the ledger at VALID LOCALLY, which is the honest thing
to say about it. Only the top state may be described as verified.

Every check runs; the report lists everything wrong, not just the first thing.
"""
from __future__ import annotations

import re
from enum import IntEnum

from .approval import verify_approval
from .errors import SchemaError


class State(IntEnum):
    INVALID = 0
    VALID_LOCALLY = 1
    BASE_VERIFIED = 2
    FULLY_VERIFIED = 3

    @staticmethod
    def text(state: "State") -> str:
        return {State.INVALID: "INVALID",
                State.VALID_LOCALLY: "VALID LOCALLY — NOT WITNESSED",
                State.BASE_VERIFIED: "BASE VERIFIED — BITCOIN PENDING",
                State.FULLY_VERIFIED: "FULLY VERIFIED"}[State(state)]


# How `ots verify` (opentimestamps-client 0.7.2) is read. Every line is matched from
# its start, never on words anywhere in the output: the output also carries paths.
#
# It could not reach a Bitcoin node (otsclient/args.py:148, cmds.py:418).
_NO_BITCOIN_NODE = ("could not connect to bitcoin node:",
                    "could not connect to local bitcoin node:")
# It moved a pending proof along, or asked a calendar that could not answer: what
# its cache and calendars said on the way (cmds.py:263, 298, 301, 306). A calendar
# URL here is on its whitelist, and a calendar's own words are cut to one line. A
# calendar's "Not found" reads the same: the server can say it for a while about a
# commitment it has only just taken (otsserver/rpc.py, its issue #10), and block.yml
# verifies seconds after stamping.
_OTS_PROGRESS = re.compile(r"got \d+ attestation\(s\) from \S+$|calendar \S+:( |$)")
# Lines that say nothing either way: the target it assumed when given no digest
# (cmds.py:473), and a calendar off the whitelist, which it will never ask
# (cmds.py:287).
_OTS_NEUTRAL = re.compile(r"assuming target filename is "
                          r"|ignoring attestation from calendar \S+: calendar not in whitelist$")
# It stopped on an exception. Every verdict it reached was printed before this, and
# nothing of its own follows. Excused only when a frame is in the calendar client: a
# calendar dropping the connection before it answers, or answering with something
# that is not a proof (a URLError becomes a "Calendar" line; these do not), and ots
# asks calendars only while a proof is incomplete. Anything else, a Bitcoin node's
# RPC error about an attestation for one, is about a proof that claims to be
# complete, and fails.
# Frame paths are Python's own, not text a proof or a calendar can supply.
_TRACEBACK = "traceback (most recent call last):"
_CALENDAR_FRAME = re.compile(r'file "[^"]*/opentimestamps/calendar\.py", line \d+')
_NO_PROOF = "no .ots proof"  # BitcoinWitness.verify, when there is no proof file at all


def _bitcoin_result(ok: bool, msg: str) -> tuple[str, str]:
    """(complete | unchecked | pending | failed, why), from ots's exit and output.

    Any line not described above is a verdict, and fails. A proof is pending only
    when ots said something about moving it towards Bitcoin (its cache or a
    calendar, even one that could not answer); one it finished with and said
    nothing about has no way there, and fails.
    """
    if ok:
        return "complete", ""
    if msg == _NO_PROOF:
        return "pending", ""
    progress = no_node = False
    lines = (msg or "").splitlines()
    for n, line in enumerate(lines):
        low = line.strip().lower()
        if not low:
            continue
        if low.startswith(_TRACEBACK):
            if any(_CALENDAR_FRAME.match(t.strip().lower()) for t in lines[n + 1:]):
                return "unchecked", "ots crashed inside its calendar client"
            return "failed", ""
        if low.startswith(_NO_BITCOIN_NODE):
            no_node = True
        elif _OTS_NEUTRAL.match(low):
            continue
        elif _OTS_PROGRESS.match(low):
            progress = True
        else:
            return "failed", ""
    if no_node:
        return "unchecked", "no Bitcoin node reachable"
    return ("pending", "") if progress else ("failed", "")


def _same_address(a, b) -> bool:
    return a is not None and b is not None and str(a).lower() == str(b).lower()


def verify_chain(ledger, trust) -> tuple[State, list[str]]:
    """Local soundness only: bytes, links, signatures, approvals, nonces, order."""
    report: list[str] = []
    failures = 0
    prev = None
    seen_nonces: dict[str, int] = {}

    try:
        blocks = list(ledger.blocks())
    except SchemaError as e:
        return State.INVALID, [f"unreadable block: {e}"]

    if not blocks:
        return State.INVALID, ["no blocks"]

    for b in blocks:
        problems: list[str] = []

        ok, why = b.verify_self()
        if not ok:
            problems.append(why)

        if b.version == 1:
            pinned = trust.legacy.get(b.index)
            if pinned is None:
                problems.append("v1 block outside the pinned legacy prefix; "
                                "format v2 is required from block 2")
            elif pinned != b.hash:
                problems.append(f"v1 block hash does not match the pinned legacy hash {pinned}")
        else:
            if not trust.approval_keys:
                problems.append("no approval keys in the trust anchor; a v2 block cannot "
                                "be checked for human approval")
            else:
                ok, why = verify_approval(b.approval, index=b.index, prev_hash=b.prev_hash,
                                          roots=b.roots, nonce=b.nonce, validator=b.validator,
                                          registered=trust.approval_keys)
                if not ok:
                    problems.append(why)
            if b.nonce in seen_nonces:
                problems.append(f"nonce reused from block {seen_nonces[b.nonce]}")
            else:
                seen_nonces[b.nonce] = b.index

        if trust.validator and b.validator != trust.validator:
            problems.append("validator is not the key pinned in the trust anchor")

        if prev is None:
            if b.index != 0:
                problems.append("chain does not start at block 0")
        else:
            if b.index != prev.index + 1:
                problems.append(f"index gap after block {prev.index}")
            if b.prev_hash != prev.hash:
                problems.append(f"prev_hash does not match block {prev.index}")
            try:
                if b.when <= prev.when:
                    problems.append(f"timestamp is not after block {prev.index}")
            except SchemaError as e:
                problems.append(str(e))

        if trust.genesis_hash and b.index == 0 and b.hash != trust.genesis_hash:
            problems.append("genesis hash does not match the trust anchor")

        if problems:
            failures += len(problems)
            for p in problems:
                report.append(f"block {b.index}: {p}")
        else:
            report.append(f"block {b.index}: ok ({len(b.roots)} roots, v{b.version})")
        prev = b

    try:
        head_idx, head_hash = ledger.head_path.read_text().split()
        if int(head_idx) != prev.index or head_hash != prev.hash:
            report.append("HEAD does not match the last block")
            failures += 1
    except (OSError, ValueError):
        report.append("HEAD is missing or unreadable")
        failures += 1

    return (State.INVALID if failures else State.VALID_LOCALLY), report


def verify_all(ledger, trust, base=None, bitcoin=None) -> tuple[State, list[str]]:
    state, report = verify_chain(ledger, trust)

    # Where the expectations came from is part of the result, whatever the outcome.
    ceiling = State.FULLY_VERIFIED
    report.append(f"trust: {trust.describe()}")
    if not trust.is_external:
        report.append("trust: witnessed states need an anchor supplied from outside this "
                      "repository; capped at VALID LOCALLY")
        ceiling = State.VALID_LOCALLY

    if state == State.INVALID:
        report.append(State.text(State.INVALID))
        return state, report

    blocks = list(ledger.blocks())
    local_head = blocks[-1].index

    if base is not None:
        failures = 0
        addr = getattr(base, "address", None)
        if trust.contract and addr is not None and not _same_address(addr, trust.contract):
            report.append(f"Base: contract {addr} is not the pinned contract {trust.contract}")
            failures += 1
        for name, pin, getter in (("genesis hash", trust.genesis_hash, "genesis_hash"),
                                  ("owner", trust.owner, "owner")):
            try:
                live = getattr(base, getter)()
            except Exception as e:  # noqa: BLE001 - a witness that cannot answer is a failure
                report.append(f"Base: could not read {name}: {e}")
                failures += 1
                continue
            if pin and live is not None:
                same = _same_address(live, pin) if name == "owner" else (live == pin)
                if not same:
                    report.append(f"Base: {name} {live} does not match the pin {pin}")
                    failures += 1

        if trust.code_keccak:
            # A pin nobody evaluated is not a pin that held, so every path out of
            # this block that is not a match counts as a failure. It goes through
            # the witness rather than through `base.w3`, because a QuorumBase has
            # no `w3` ~ reaching for one skipped the check on exactly the setup
            # that was meant to be the more careful one.
            reader = getattr(base, "code_hash", None)
            if reader is None:
                report.append("Base: a deployed code hash is pinned, and this witness "
                              "offers no way to read it")
                failures += 1
            else:
                try:
                    live = reader()
                except Exception as e:  # noqa: BLE001 - a witness that cannot answer is a failure
                    report.append(f"Base: could not read the deployed code hash: {e}")
                    failures += 1
                else:
                    # Bare lowercase hex on both sides. `.lstrip("0x")` here would eat
                    # a digest's leading zeros and compare two different things.
                    if live != trust.code_keccak:
                        report.append(f"Base: deployed code hash {live} does not match "
                                      f"the pin {trust.code_keccak}")
                        failures += 1

        try:
            latest = base.latest_index()
        except Exception as e:  # noqa: BLE001
            report.append(f"Base: could not read latestIndex: {e}")
            latest, failures = None, failures + 1

        if latest is not None:
            if latest > local_head:
                report.append(f"Base: contract latestIndex is {latest}, the local chain ends at "
                              f"{local_head}; the local copy is truncated")
                failures += 1
            for b in blocks:
                if b.index > min(latest, local_head):
                    break
                if not base.matches(b):
                    report.append(f"block {b.index}: Base holds a different hash")
                    failures += 1
                    continue
                try:
                    rec = base.record(b.index)
                except Exception:  # noqa: BLE001
                    rec = None
                if rec and rec.get("anchoredAt"):
                    if int(rec["anchoredAt"]) < int(b.when.timestamp()):
                        report.append(f"block {b.index}: Base anchoredAt "
                                      f"{rec['anchoredAt']} precedes the block's own timestamp")
                        failures += 1
                if rec and trust.owner and rec.get("by") and not _same_address(rec["by"], trust.owner):
                    report.append(f"block {b.index}: anchored by {rec['by']}, not the pinned owner")
                    failures += 1

        if failures:
            return State.INVALID, report

        if latest is not None and local_head > latest:
            for i in range(latest + 1, local_head + 1):
                report.append(f"block {i}: written but not anchored on Base")
            ceiling = min(ceiling, State.VALID_LOCALLY)
        else:
            report.append(f"Base: {min(latest, local_head) + 1} block(s) anchored and matching")
            state = State.BASE_VERIFIED

    if bitcoin is not None:
        pending = 0
        for b in blocks:
            ok, msg = bitcoin.verify(b)
            result, why = _bitcoin_result(ok, msg)
            if result == "complete":
                report.append(f"block {b.index}: Bitcoin proof complete")
            elif result == "unchecked":
                # A complete proof is checked against a Bitcoin node. Without one,
                # or with ots crashing inside its calendar client, it is unchecked,
                # which is not the same as wrong. ots goes on to the next attestation
                # after a failed connection, so a real verdict can sit beside it; then
                # the result is "failed".
                report.append(f"block {b.index}: Bitcoin proof not checked, {why}: {msg}")
                pending += 1
            elif result == "pending":
                report.append(f"block {b.index}: Bitcoin proof pending: {msg}")
                pending += 1
            else:
                report.append(f"block {b.index}: Bitcoin proof FAILED: {msg}")
                return State.INVALID, report
        if not pending and state >= State.BASE_VERIFIED:
            state = State.FULLY_VERIFIED

    final = State(min(int(state), int(ceiling)))
    report.append(State.text(final))
    return final, report
