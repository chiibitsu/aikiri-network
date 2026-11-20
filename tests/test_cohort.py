"""Certificate cohorts: one Merkle root per block, one proof per certificate.

Every fingerprint here is sha256 of an obviously fake string ("test-cert-1", ...).
No real certificate, person or course is in this file, and none may be.
"""
import hashlib
import json
from pathlib import Path

import pytest

from aikiri_ledger import cli, cohort
from aikiri_ledger.errors import SchemaError
from aikiri_ledger.request import ROOT_KINDS, parse_roots

from test_seal import checkout, fake_approve, land, mac, run, sk, snapshot, world, _git  # noqa: F401

VECTORS = json.loads((Path(__file__).parent / "vectors" / "cert_cohort.json").read_text())


def fake(i: int) -> str:
    return hashlib.sha256(f"test-cert-{i}".encode()).hexdigest()


FIVE = [fake(i) for i in range(1, 6)]


# --- an independent RFC 9162 Merkle Tree Hash, to hold the module to ---------------------

def rfc9162(data: list[bytes], leaf=b"\x00", node=b"\x01") -> bytes:
    """MTH from RFC 9162 section 2.1.1, written apart from aikiri_ledger/cohort.py."""
    n = len(data)
    if n == 1:
        return hashlib.sha256(leaf + data[0]).digest()
    k = 1 << ((n - 1).bit_length() - 1)   # largest power of two below n
    return hashlib.sha256(node + rfc9162(data[:k], leaf, node) + rfc9162(data[k:], leaf, node)).digest()


# The 8-entry test tree used across Certificate Transparency implementations, with the
# RFC's own 0x00 / 0x01 prefixes: proves the reference above has the RFC's shape.
CT_LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43",
             bytes(range(0x50, 0x58)), bytes(range(0x60, 0x70))]
CT_ROOTS = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]


def test_the_reference_is_rfc_9162_on_the_ct_test_tree():
    for n in range(1, 9):
        assert rfc9162(CT_LEAVES[:n]).hex() == CT_ROOTS[n - 1]


@pytest.mark.parametrize("n", list(range(1, 34)))
def test_root_and_every_proof_match_the_rfc_shape_with_our_prefixes(n):
    fps = [fake(i) for i in range(1, n + 1)]
    want = rfc9162([bytes.fromhex(f) for f in sorted(fps)],
                   cohort.LEAF_DOMAIN, cohort.NODE_DOMAIN).hex()
    root, proofs = cohort.build(fps)
    assert root == want == cohort.root(fps)
    assert len(proofs) == n
    for p in proofs:
        assert cohort.verify_proof(p)
        assert len(p["path"]) <= max(1, (n - 1).bit_length())


# --- golden vectors -----------------------------------------------------------------

def test_golden_cohort_vectors_exact():
    assert VECTORS["leaf_domain"] == "aikiri-ledger/cert-leaf/v1\n" == cohort.LEAF_DOMAIN.decode()
    assert VECTORS["node_domain"] == "aikiri-ledger/cert-node/v1\n" == cohort.NODE_DOMAIN.decode()
    assert VECTORS["inputs"] == {f"test-cert-{i}": fake(i) for i in range(1, 6)}
    for fp, h in VECTORS["leaf_hashes"].items():
        assert cohort.leaf_hash(fp).hex() == h
    for c in VECTORS["cohorts"]:
        root, proofs = cohort.build(c["leaves"])
        assert root == c["root"]
        assert proofs == c["proofs"]
        assert [cohort.proof_json(p) for p in proofs] == [cohort.proof_json(p) for p in c["proofs"]]


def test_golden_roots_pinned_here_too():
    # Pinned in the test as well as the file, so editing the file alone cannot move them.
    assert cohort.root(FIVE[:1]) == "8e0280ff099081f742691677992d5aeb53313c76be89065a94e604ef0ed41ae5"
    assert cohort.root(FIVE[:3]) == "10949e1184ea55ef18a67f463c7e6ed446a649bc460701476d1ce6dedb36b29e"
    assert cohort.root(FIVE) == "845e6fb6fff5a48ff2aa3ca8760b92801160bd75b68ba5e1ea8b085dfa4e17cd"


def test_golden_proof_bytes():
    _, proofs = cohort.build(FIVE[:3])
    assert cohort.proof_json(proofs[2]) == (
        '{"block":null,"leaf":"c39e4fe697b07d0fe9a736040be03c09d772e852a33f1658e40281851bc15043",'
        '"path":[{"sha256":"aaebe2dfe7eae0d9937a8c563ed45dc5628a3b566a0d2aa9f0c08b740d5e07e9",'
        '"side":"left"}],"root":"10949e1184ea55ef18a67f463c7e6ed446a649bc460701476d1ce6dedb36b29e",'
        '"v":1}\n')


# --- the tree's rules ---------------------------------------------------------------

def test_order_does_not_matter():
    assert cohort.root(FIVE) == cohort.root(list(reversed(FIVE))) == cohort.root(sorted(FIVE))


def test_a_single_certificate_cohort():
    root, [p] = cohort.build([FIVE[0]])
    assert p["path"] == []
    assert root == cohort.leaf_hash(FIVE[0]).hex() != FIVE[0]
    assert cohort.verify_proof(p)


@pytest.mark.parametrize("n", [3, 5, 7])
def test_odd_counts_carry_the_last_leaf_up_without_duplicating_it(n):
    fps = sorted(FIVE + [fake(6), fake(7)])[:n]
    root, proofs = cohort.build(fps)
    # The last leaf has a shorter path than the first: it was carried up, never paired with itself.
    assert len(proofs[-1]["path"]) < len(proofs[0]["path"])
    assert all(s["sha256"] != cohort.leaf_hash(fps[-1]).hex() for s in proofs[-1]["path"])
    # And no padded copy of the cohort shares its root (v1's [a,b,c] = [a,b,c,c]).
    with pytest.raises(SchemaError, match="twice"):
        cohort.root(fps + [fps[-1]])
    assert cohort.root(fps[:-1]) != root


def test_a_leaf_cannot_pose_as_a_node():
    """An inner node presented as a certificate, with the rest of the path, does not verify."""
    fps = FIVE[:4]
    root, proofs = cohort.build(fps)
    inner = cohort.node_hash(cohort.leaf_hash(sorted(fps)[0]), cohort.leaf_hash(sorted(fps)[1])).hex()
    forged = {"v": 1, "leaf": inner, "root": root, "block": None, "path": proofs[0]["path"][1:]}
    assert not cohort.verify_proof(forged)
    assert cohort.LEAF_DOMAIN != cohort.NODE_DOMAIN


def test_empty_duplicate_and_oversized_cohorts_are_refused(monkeypatch):
    with pytest.raises(SchemaError, match="at least one"):
        cohort.leaves([])
    with pytest.raises(SchemaError, match="twice"):
        cohort.leaves([FIVE[0], FIVE[0]])
    monkeypatch.setattr(cohort, "MAX_LEAVES", 4)
    with pytest.raises(SchemaError, match="at most 4"):
        cohort.leaves(FIVE)


def test_the_fingerprint_file_contract():
    text = f"{FIVE[0]}\n\n  0x{FIVE[1].upper()}  \n{FIVE[2]}"
    assert cohort.read_fingerprints(text) == FIVE[:3]
    for bad in ("abc", FIVE[0][:-1], FIVE[0] + "0", "g" * 64, f"{FIVE[0]} {FIVE[1]}",
                f"{FIVE[0]},", "# a comment"):
        with pytest.raises(SchemaError, match="line 2"):
            cohort.read_fingerprints(f"{FIVE[0]}\n{bad}\n")


# --- tampered proofs and wrong roots --------------------------------------------------

def _tamper(p, how):
    p = json.loads(json.dumps(p))
    if how == "flip-side":
        p["path"][0]["side"] = "left" if p["path"][0]["side"] == "right" else "right"
    elif how == "sibling":
        s = p["path"][0]["sha256"]; p["path"][0]["sha256"] = ("0" if s[0] != "0" else "1") + s[1:]
    elif how == "drop-step":
        p["path"].pop()
    elif how == "add-step":
        p["path"].append({"side": "left", "sha256": "00" * 32})
    elif how == "swap-steps":
        p["path"].reverse()
    elif how == "leaf":
        p["leaf"] = fake(99)
    elif how == "root":
        p["root"] = cohort.root(FIVE[:3])
    elif how == "extra-field":
        p["note"] = "x"
    elif how == "missing-field":
        del p["block"]
    elif how == "version":
        p["v"] = 2
    elif how == "uppercase":
        p["leaf"] = p["leaf"].upper()
    elif how == "bad-side":
        p["path"][0]["side"] = "up"
    elif how == "bool-version":
        p["v"] = True
    elif how == "long-path":
        p["path"] = p["path"] + [{"side": "left", "sha256": "00" * 32}] * cohort.MAX_PATH
    return p


@pytest.mark.parametrize("how", ["flip-side", "sibling", "drop-step", "add-step", "swap-steps",
                                 "leaf", "root", "extra-field", "missing-field", "version",
                                 "uppercase", "bad-side", "bool-version", "long-path"])
def test_a_tampered_proof_does_not_verify(how):
    _, proofs = cohort.build(FIVE)
    p = proofs[1]
    assert cohort.verify_proof(p)
    assert not cohort.verify_proof(_tamper(p, how))


def test_a_proof_never_verifies_against_another_cohorts_root():
    _, a = cohort.build(FIVE[:4])
    other = cohort.root(FIVE)
    for p in a:
        assert not cohort.verify_proof({**p, "root": other})


def test_verify_proof_is_false_not_an_exception_for_junk():
    for junk in (None, 1, "", "{", "[]", {"v": 1}, b"\xff", "NaN"):
        assert cohort.verify_proof(junk) is False


# --- the ledger side: seal, verify, revoke ---------------------------------------------

def write_fps(tmp_path, fps):
    f = tmp_path / "fingerprints.txt"
    f.write_text("\n".join(fps) + "\n")
    return f


def test_the_kind_is_known_and_still_one_root_per_block():
    assert "cert-cohort" in ROOT_KINDS
    root = cohort.root(FIVE)
    assert parse_roots([{"kind": "cert-cohort", "sha256": root}]) == [{"kind": "cert-cohort", "sha256": root}]
    with pytest.raises(SchemaError, match="exactly one root"):
        parse_roots([{"kind": "cert-cohort", "sha256": root}, {"kind": "cert-cohort", "sha256": FIVE[0]}])


def test_build_writes_proofs_and_touches_no_ledger(world, tmp_path, capsys):
    L, trust, tf = world
    before = snapshot(L)
    out = tmp_path / "proofs"
    assert run(L, tf, "cohort", "build", str(write_fps(tmp_path, FIVE)), "--out", str(out)) == 0
    assert snapshot(L) == before
    assert (out / "root.txt").read_text() == cohort.root(FIVE) + "\n"
    files = sorted(p.name for p in out.iterdir())
    assert files == sorted([f"{f}.json" for f in FIVE] + ["root.txt"])
    for f in FIVE:
        p = cohort.parse_proof((out / f"{f}.json").read_text())
        assert p["leaf"] == f and p["block"] is None and cohort.verify_proof(p)
    assert cohort.root(FIVE) in capsys.readouterr().out


def test_seal_a_cohort_then_verify_then_revoke_one(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    out = tmp_path / "proofs"
    fps = write_fps(tmp_path, FIVE)
    root = cohort.root(FIVE)

    assert run(L, tf, "cohort", "seal", str(fps), "--out", str(out)) == 0
    req = json.loads((L.requests_dir / "next.json").read_text())
    assert req["roots"] == [{"kind": "cert-cohort", "sha256": root}]
    assert all(cohort.parse_proof((out / f"{f}.json").read_text())["block"] == req["index"] for f in FIVE)

    # Before the block lands the proof is sound but not sealed.
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(out / f"{FIVE[0]}.json")) == 1
    assert capsys.readouterr().out.startswith("NOT SEALED")

    blk = land(L, sk, mac, 1)
    assert blk.index == req["index"] and blk.roots == req["roots"]
    for f in FIVE:
        assert run(L, tf, "cohort", "verify", str(out / f"{f}.json")) == 0
    said = capsys.readouterr().out
    assert said.count("VALID  certificate") == 5 and f"sealed in block {blk.index}" in said
    assert "ledger: VALID LOCALLY" in said

    # Revoke the third: its fingerprint, sealed under the existing revocation kind.
    victim = out / f"{FIVE[2]}.json"
    assert run(L, tf, "cohort", "revoke", str(victim)) == 0
    rreq = json.loads((L.requests_dir / "next.json").read_text())
    assert rreq["roots"] == [{"kind": "revocation", "sha256": FIVE[2]}]
    rblk = land(L, sk, mac, 2)

    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(victim)) == 1
    said = capsys.readouterr().out
    assert said.startswith("REVOKED  certificate " + FIVE[2])
    assert f"revoked in block {rblk.index}" in said
    for f in FIVE[:2] + FIVE[3:]:
        assert run(L, tf, "cohort", "verify", str(out / f"{f}.json")) == 0

    # Revoking again changes nothing.
    before = snapshot(L)
    assert run(L, tf, "cohort", "revoke", str(victim)) == 0
    assert snapshot(L) == before


def test_a_repeat_seal_changes_nothing(world, sk, mac, tmp_path):
    L, trust, tf = world
    out = tmp_path / "proofs"
    fps = write_fps(tmp_path, FIVE)
    assert run(L, tf, "cohort", "seal", str(fps), "--out", str(out)) == 0
    before, proofs = snapshot(L), {p.name: p.read_bytes() for p in out.iterdir()}
    assert run(L, tf, "cohort", "seal", str(fps), "--out", str(out)) == 0
    assert snapshot(L) == before
    assert {p.name: p.read_bytes() for p in out.iterdir()} == proofs

    blk = land(L, sk, mac, 1)
    before = snapshot(L)
    assert run(L, tf, "cohort", "seal", str(fps), "--out", str(out)) == 0   # sealed: no request
    assert snapshot(L) == before and not (L.requests_dir / "next.json").exists()
    assert cohort.parse_proof((out / f"{FIVE[0]}.json").read_text())["block"] == blk.index


def test_seal_after_build_fills_in_the_block(world, tmp_path):
    L, trust, tf = world
    out = tmp_path / "proofs"
    fps = write_fps(tmp_path, FIVE)
    assert run(L, tf, "cohort", "build", str(fps), "--out", str(out)) == 0
    assert run(L, tf, "cohort", "seal", str(fps), "--out", str(out)) == 0
    assert cohort.parse_proof((out / f"{FIVE[0]}.json").read_text())["block"] == 1


def test_one_request_at_a_time(world, tmp_path):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE)), "--out", str(tmp_path / "a")) == 0
    with pytest.raises(SystemExit, match="one block, one request"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE[:2])), "--out", str(tmp_path / "b"))
    assert not (tmp_path / "b").exists()


def test_a_folder_holding_anything_else_is_refused(world, tmp_path):
    L, trust, tf = world
    fps = write_fps(tmp_path, FIVE)
    other = tmp_path / "other"
    assert run(L, tf, "cohort", "build", str(write_fps(tmp_path, FIVE[:2])), "--out", str(other)) == 0
    fps = write_fps(tmp_path, FIVE)
    with pytest.raises(SystemExit, match="another cohort"):
        run(L, tf, "cohort", "seal", str(fps), "--out", str(other))
    stray = tmp_path / "stray"
    stray.mkdir(); (stray / "notes.txt").write_text("x")
    with pytest.raises(SystemExit, match="not this cohort's"):
        run(L, tf, "cohort", "build", str(fps), "--out", str(stray))
    assert not (L.requests_dir / "next.json").exists()


def test_a_bad_fingerprint_file_is_refused_with_nothing_written(world, tmp_path):
    L, trust, tf = world
    f = tmp_path / "fps.txt"
    f.write_text(f"{FIVE[0]}\nnot-a-fingerprint\n")
    before = snapshot(L)
    with pytest.raises(SystemExit, match="line 2"):
        run(L, tf, "cohort", "seal", str(f), "--out", str(tmp_path / "out"))
    assert snapshot(L) == before and not (tmp_path / "out").exists()


def test_verify_says_invalid_for_a_tampered_proof_and_a_wrong_block(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    out = tmp_path / "proofs"
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE)), "--out", str(out)) == 0
    land(L, sk, mac, 1)
    good = cohort.parse_proof((out / f"{FIVE[0]}.json").read_text())

    for bad in (_tamper(good, "sibling"), {**good, "block": 7}):
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(bad))
        capsys.readouterr()
        assert run(L, tf, "cohort", "verify", str(f)) == 1
        assert capsys.readouterr().out.startswith("INVALID")
    with pytest.raises(SystemExit, match="refused: INVALID"):
        run(L, tf, "cohort", "revoke", str(f))


def test_a_proof_of_a_cohort_never_sealed_is_not_sealed(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE)), "--out", str(tmp_path / "a")) == 0
    land(L, sk, mac, 1)
    assert run(L, tf, "cohort", "build", str(write_fps(tmp_path, FIVE[:4])), "--out", str(tmp_path / "b")) == 0
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(tmp_path / "b" / f"{FIVE[0]}.json")) == 1
    assert capsys.readouterr().out.startswith("NOT SEALED")
    with pytest.raises(SystemExit, match="refused: NOT SEALED"):
        run(L, tf, "cohort", "revoke", str(tmp_path / "b" / f"{FIVE[0]}.json"))


def test_a_root_sealed_as_another_kind_does_not_count(world, sk, mac, tmp_path, capsys):
    """Only a cert-cohort block seals a cohort: the same hash sealed as a revocation is not one."""
    L, trust, tf = world
    _, [p] = cohort.build([FIVE[0]])
    pf = tmp_path / "p.json"; pf.write_text(cohort.proof_json(p))
    assert run(L, tf, "cohort", "build", str(write_fps(tmp_path, [FIVE[0]])), "--out", str(tmp_path / "x")) == 0
    # A revocation block whose root happens to be the cohort root.
    from aikiri_ledger.request import Request
    head = L.head()
    (L.requests_dir).mkdir(parents=True, exist_ok=True)
    (L.requests_dir / "next.json").write_text(json.dumps(Request.unsigned(
        index=head.index + 1, prev_hash=head.hash, roots=[{"kind": "revocation", "sha256": p["root"]}],
        validator=head.validator)))
    land(L, sk, mac, 1)
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(pf)) == 1
    assert capsys.readouterr().out.startswith("NOT SEALED")
    with pytest.raises(SystemExit, match="already sealed as revocation"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, [FIVE[0]])), "--out", str(tmp_path / "y"))


def test_cohort_seal_push_commits_only_the_request(checkout, mac, monkeypatch, tmp_path_factory):
    L, tf, repo, remote = checkout
    monkeypatch.setattr(cli, "_approve", fake_approve(mac))
    elsewhere = tmp_path_factory.mktemp("issuer")
    fps = write_fps(elsewhere, FIVE)
    assert run(L, tf, "cohort", "seal", str(fps), "--out", str(elsewhere / "proofs"), "--push") == 0
    pushed = _git(remote, "log", "-1", "--name-only", "--format=%s", "main").split()
    assert pushed == ["Request", "block", "1", "ledger/requests/next.json"]
    sealed = json.loads(_git(remote, "show", "main:ledger/requests/next.json"))
    assert sealed["approval"]["device"] == "mac"
    assert sealed["roots"] == [{"kind": "cert-cohort", "sha256": cohort.root(FIVE)}]
    for f in FIVE:   # no fingerprint of a single certificate travels with the cohort's block
        assert f not in _git(remote, "show", "main:ledger/requests/next.json")


def test_nothing_personal_in_the_vectors():
    """The vectors hold hashes of the fake strings and nothing else."""
    text = (Path(__file__).parent / "vectors" / "cert_cohort.json").read_text()
    words = set(json.loads(text)["inputs"])
    assert words == {f"test-cert-{i}" for i in range(1, 6)}
