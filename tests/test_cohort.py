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


# --- the issuer record: format, fingerprint, link payload --------------------------------

RECORD = {"v": 1, "number": "00112233445566778899aabbccddeeff", "holder": "Test Holder",
          "course": "Example Course", "completed": "2026-01-31", "issuer": "Chiibitsu Labs",
          "instructor": "Test Instructor"}


def test_golden_record_vectors_exact():
    R = VECTORS["records"]
    assert R["record_domain"] == "aikiri-ledger/cert-record/v1\n" == cohort.RECORD_DOMAIN.decode()
    assert R["issuer"] == "Chiibitsu Labs" == cohort.ISSUER
    for ex in R["examples"]:
        b = cohort.record_bytes(ex["record"])
        assert b.hex() == ex["canonical_utf8_hex"] and b.decode("utf-8") == ex["canonical"]
        assert hashlib.sha256(cohort.RECORD_DOMAIN + b).hexdigest() == ex["fingerprint"]
        assert cohort.record_fingerprint(ex["record"]) == ex["fingerprint"]
        assert cohort.encode_payload(ex["record"]) == ex["payload"]
        assert cohort.decode_payload(ex["payload"]) == cohort.parse_record(ex["record"])
    fps = [ex["fingerprint"] for ex in R["examples"]]
    assert [c["size"] for c in R["cohorts"]] == [1, 2, 3]
    for c in R["cohorts"]:
        root, proofs = cohort.build(fps[:c["size"]], block=c["block"])
        assert root == c["root"] and proofs == c["proofs"] and c["leaves"] == sorted(fps[:c["size"]])
    for fp, f in R["revoked_files"].items():
        assert cohort.revoked_json(fp, f["block"]) == json.dumps(f, sort_keys=True, separators=(",", ":")) + "\n"


class _Blk:
    def __init__(self, d): self.index, self.timestamp, self.roots = d["index"], d["timestamp"], d["roots"]


class _Ledger:
    """Only what a reader takes from ledger/blocks/: index, timestamp, roots."""
    def __init__(self, blocks): self._b = [_Blk(d) for d in blocks]
    def blocks(self): return iter(self._b)


def test_golden_expected_verdicts_from_the_sample_blocks():
    R = VECTORS["records"]
    L = _Ledger(R["blocks"])
    for c in R["cohorts"]:
        got = {p["leaf"]: cohort.status(p, L)[0] for p in c["proofs"]}
        assert got == R["expected_by_cohort"][str(c["size"])]
    assert sorted(R["expected_by_cohort"]["3"].values()) == ["REVOKED", "VALID", "VALID"]


def test_golden_reader_cases():
    R = VECTORS["records"]
    L = _Ledger(R["blocks"])
    assert {c["expected"] for c in R["reader_cases"]} == {"VALID", "REVOKED", "NOT FOUND", "INVALID"}
    assert any(c["file"] != f'{c["proof"]["leaf"]}.json' for c in R["reader_cases"])
    for c in R["reader_cases"]:
        assert cohort.status_of_file(c["file"], c["proof"], L)[0] == c["expected"], c["case"]


def test_golden_revoked_file_cases():
    R = VECTORS["records"]
    blocks = {b["index"]: b for b in R["blocks"]}
    for c in R["revoked_file_cases"]:
        f = cohort.parse_revoked(c["file"])
        blk = blocks.get(f["block"])
        counts = blk is not None and blk["roots"] == [{"kind": "revocation", "sha256": f["fingerprint"]}]
        assert counts == c["counts"], c["case"]


def test_golden_record_pinned_here_too():
    assert cohort.record_fingerprint(RECORD) == "209fad06c360f203a8c3abb18172127c71d742680bb23a3c4deab40025f08e7d"
    raw = bytes.fromhex(VECTORS["records"]["examples"][2]["canonical_utf8_hex"])
    assert '"T\u00ebst H\u014dlder \\"Three\\" \\\\ Example"'.encode() in raw  # UTF-8 as is; " and \ escaped
    assert "\U0001F393".encode() in raw and b"\\u" not in raw               # no \u escapes at all


def test_the_canonical_bytes_are_what_a_browser_gives():
    """JSON.stringify of a sorted object: the same rules, spelled out in Python."""
    for ex in VECTORS["records"]["examples"]:
        r = cohort.parse_record(ex["record"])
        js = "{" + ",".join(json.dumps(k) + ":" + (str(v) if isinstance(v, int) else
                            '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"')
                            for k, v in sorted(r.items())) + "}"
        assert js.encode("utf-8") == cohort.record_bytes(r)


def test_issuer_is_fixed_in_format_v1():
    with pytest.raises(SchemaError, match="Chiibitsu Labs"):
        cohort.parse_record({**RECORD, "issuer": "Example Issuer"})
    with pytest.raises(SchemaError):
        cohort.parse_record({**RECORD, "issuer": "chiibitsu labs"})


def test_host_is_optional_and_only_where_given():
    with_host = {**RECORD, "host": "Example Host"}
    assert "host" not in cohort.parse_record(RECORD)
    assert cohort.parse_record(with_host)["host"] == "Example Host"
    assert cohort.record_fingerprint(with_host) != cohort.record_fingerprint(RECORD)
    for bad in ("", None, 3):
        with pytest.raises(SchemaError):
            cohort.parse_record({**RECORD, "host": bad})


@pytest.mark.parametrize("change", [
    {"number": "00" * 15},                 # 120 bits: too few
    {"number": "00" * 33},                 # too long
    {"number": "0" * 33},                  # odd length
    {"number": "AA" * 16},                 # capitals
    {"completed": "2026-02-30"}, {"completed": "2026-1-31"}, {"completed": "31/01/2026"},
    {"v": 2}, {"v": True}, {"holder": ""}, {"holder": "x" * 201}, {"holder": "a\nb"},
    {"holder": "e\u0301"},               # not NFC
    {"holder": "\ud800"},                # a lone surrogate
    {"extra": "x"},
])
def test_a_bad_record_is_refused(change):
    with pytest.raises(SchemaError):
        cohort.parse_record({**RECORD, **change})


def test_every_required_field_is_required():
    for k in cohort.RECORD_FIELDS:
        with pytest.raises(SchemaError):
            cohort.parse_record({f: v for f, v in RECORD.items() if f != k})


def test_payload_is_read_from_a_link_and_only_in_canonical_form():
    pl = cohort.encode_payload(RECORD)
    assert "=" not in pl
    assert cohort.decode_payload(f"https://example.test/network/cert#{pl}") == RECORD
    import base64
    loose = base64.urlsafe_b64encode(json.dumps(RECORD).encode()).rstrip(b"=").decode()
    for bad in (pl + "=", pl[:-1], pl + "A", loose, "", "#", "not base64!", "A" * 5000):
        with pytest.raises(SchemaError):
            cohort.decode_payload(bad)


# --- the ledger side: seal, verify, revoke ---------------------------------------------

def write_fps(tmp_path, fps):
    f = tmp_path / "fingerprints.txt"
    f.write_text("\n".join(fps) + "\n")
    return f


def certs(L):
    return L.root / "certs"


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


def test_the_public_files_hold_hashes_only(world, sk, mac, tmp_path):
    """ledger/certs/<fp>.json and ledger/certs/revoked/<fp>.json: no record field, ever."""
    L, trust, tf = world
    recs = [{**RECORD, "number": f"{i:02x}" * 16, "holder": f"Test Holder {i}"} for i in range(1, 4)]
    recs[0]["host"] = "Example Host"
    fps = [cohort.record_fingerprint(r) for r in recs]
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, fps))) == 0
    land(L, sk, mac, 1)
    assert run(L, tf, "cohort", "revoke", str(certs(L) / f"{fps[0]}.json")) == 0
    public = [p for p in certs(L).rglob("*") if p.is_file()]
    assert sorted(p.name for p in public) == sorted([f"{f}.json" for f in fps] + [f"{fps[0]}.json"])
    words = {w for r in recs for k, v in r.items() if k not in ("v", "completed") for w in [v]}
    for p in public:
        text = p.read_text()
        for w in words | {"Test", "Example", "Holder", "Course", "Host"}:
            assert w not in text, (p, w)
    assert set(json.loads((certs(L) / "revoked" / f"{fps[0]}.json").read_text())) == {"v", "fingerprint", "block"}


def test_seal_a_cohort_then_verify_then_revoke_one(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    fps = write_fps(tmp_path, FIVE)
    root = cohort.root(FIVE)

    assert run(L, tf, "cohort", "seal", str(fps)) == 0
    req = json.loads((L.requests_dir / "next.json").read_text())
    assert req["roots"] == [{"kind": "cert-cohort", "sha256": root}]
    assert all(cohort.parse_proof((certs(L) / f"{f}.json").read_text())["block"] == req["index"] for f in FIVE)
    assert not (certs(L) / "root.txt").exists()

    # Before the block lands the proof is sound but not sealed.
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(certs(L) / f"{FIVE[0]}.json")) == 1
    assert capsys.readouterr().out.startswith("NOT FOUND")

    blk = land(L, sk, mac, 1)
    assert blk.index == req["index"] and blk.roots == req["roots"]
    for f in FIVE:
        assert run(L, tf, "cohort", "verify", str(certs(L) / f"{f}.json")) == 0
    said = capsys.readouterr().out
    assert said.count("VALID  certificate") == 5 and f"sealed in block {blk.index}" in said
    assert "ledger: VALID LOCALLY" in said

    # Revoke the third: its fingerprint, sealed under the existing revocation kind.
    victim = certs(L) / f"{FIVE[2]}.json"
    assert run(L, tf, "cohort", "revoke", str(victim)) == 0
    rreq = json.loads((L.requests_dir / "next.json").read_text())
    assert rreq["roots"] == [{"kind": "revocation", "sha256": FIVE[2]}]
    mark = cohort.parse_revoked((certs(L) / "revoked" / f"{FIVE[2]}.json").read_text())
    assert mark == {"v": 1, "fingerprint": FIVE[2], "block": rreq["index"]}

    # Requested, not yet in a block: still valid, and verify says a revocation is waiting.
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(victim)) == 0
    assert "a revocation is requested" in capsys.readouterr().out

    rblk = land(L, sk, mac, 2)
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(victim)) == 1
    said = capsys.readouterr().out
    assert said.startswith("REVOKED  certificate " + FIVE[2])
    assert f"revoked in block {rblk.index}" in said
    for f in FIVE[:2] + FIVE[3:]:
        assert run(L, tf, "cohort", "verify", str(certs(L) / f"{f}.json")) == 0

    # Revoking again changes nothing.
    before = snapshot(L)
    assert run(L, tf, "cohort", "revoke", str(victim)) == 0
    assert snapshot(L) == before


def test_a_revoked_file_alone_revokes_nothing(world, sk, mac, tmp_path, capsys):
    """The pointer file is not evidence: only a revocation block is."""
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    land(L, sk, mac, 1)
    (certs(L) / "revoked").mkdir()
    (certs(L) / "revoked" / f"{FIVE[0]}.json").write_text(cohort.revoked_json(FIVE[0], 2))
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(certs(L) / f"{FIVE[0]}.json")) == 0
    assert capsys.readouterr().out.startswith("VALID")


def test_verify_takes_a_record_or_a_link_payload(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    recs = [{**RECORD, "number": f"{i:02x}" * 16} for i in range(1, 4)]
    fps = [cohort.record_fingerprint(r) for r in recs]
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, fps))) == 0
    land(L, sk, mac, 1)
    rf = tmp_path / "record.json"; rf.write_text(json.dumps(recs[1]))
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(rf)) == 0
    assert run(L, tf, "cohort", "verify", "https://example.test/network/cert#" + cohort.encode_payload(recs[2])) == 0
    said = capsys.readouterr().out
    assert said.count("VALID  certificate") == 2 and fps[1] in said and fps[2] in said
    assert "Test Holder" not in said    # verify prints the fingerprint, never the record

    stranger = {**RECORD, "number": "ab" * 16}
    assert run(L, tf, "cohort", "verify", cohort.encode_payload(stranger)) == 1
    assert capsys.readouterr().out.startswith("NOT FOUND  certificate " + cohort.record_fingerprint(stranger))
    assert run(L, tf, "cohort", "verify", "#not-a-payload") == 1
    assert capsys.readouterr().out.startswith("INVALID")

    # A proof file put under another certificate's name is caught.
    (certs(L) / f"{cohort.record_fingerprint(stranger)}.json").write_text(
        (certs(L) / f"{fps[0]}.json").read_text())
    assert run(L, tf, "cohort", "verify", cohort.encode_payload(stranger)) == 1
    assert "proof of another certificate" in capsys.readouterr().out


def test_a_repeat_seal_changes_nothing(world, sk, mac, tmp_path):
    L, trust, tf = world
    fps = write_fps(tmp_path, FIVE)
    assert run(L, tf, "cohort", "seal", str(fps)) == 0
    before = snapshot(L)
    assert run(L, tf, "cohort", "seal", str(fps)) == 0
    assert snapshot(L) == before

    blk = land(L, sk, mac, 1)
    before = snapshot(L)
    assert run(L, tf, "cohort", "seal", str(fps)) == 0   # sealed: no request, same proofs
    assert snapshot(L) == before and not (L.requests_dir / "next.json").exists()
    assert cohort.parse_proof((certs(L) / f"{FIVE[0]}.json").read_text())["block"] == blk.index


def test_one_request_at_a_time(world, tmp_path):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    before = snapshot(L)
    with pytest.raises(SystemExit, match="one block, one request"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, [fake(8), fake(9)])))
    assert snapshot(L) == before


def test_a_certificate_is_in_one_cohort_only(world, sk, mac, tmp_path):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE[:3]))) == 0
    land(L, sk, mac, 1)
    before = snapshot(L)
    with pytest.raises(SystemExit, match="in one cohort only"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE[2:])))
    assert snapshot(L) == before


def test_a_build_folder_holding_anything_else_is_refused(world, tmp_path):
    L, trust, tf = world
    other = tmp_path / "other"
    assert run(L, tf, "cohort", "build", str(write_fps(tmp_path, FIVE[:2])), "--out", str(other)) == 0
    fps = write_fps(tmp_path, FIVE)
    with pytest.raises(SystemExit, match="another cohort"):
        run(L, tf, "cohort", "build", str(fps), "--out", str(other))
    stray = tmp_path / "stray"
    stray.mkdir(); (stray / "notes.txt").write_text("x")
    with pytest.raises(SystemExit, match="not this cohort's"):
        run(L, tf, "cohort", "build", str(fps), "--out", str(stray))


def test_a_linked_certs_folder_or_proof_is_refused(world, tmp_path):
    L, trust, tf = world
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir()
    certs(L).symlink_to(elsewhere)
    with pytest.raises(SystemExit, match="not a folder"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE)))
    certs(L).unlink(); certs(L).mkdir()
    (certs(L) / f"{FIVE[0]}.json").symlink_to(elsewhere / "x.json")
    with pytest.raises(SystemExit, match="is a link"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE)))
    assert not (L.requests_dir / "next.json").exists() and not (elsewhere / "x.json").exists()


def test_a_bad_fingerprint_file_is_refused_with_nothing_written(world, tmp_path):
    L, trust, tf = world
    f = tmp_path / "fps.txt"
    f.write_text(f"{FIVE[0]}\nnot-a-fingerprint\n")
    before = snapshot(L)
    with pytest.raises(SystemExit, match="line 2"):
        run(L, tf, "cohort", "seal", str(f))
    assert snapshot(L) == before


def test_verify_says_invalid_for_a_tampered_proof_and_a_wrong_block(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    land(L, sk, mac, 1)
    good = cohort.parse_proof((certs(L) / f"{FIVE[0]}.json").read_text())

    for bad, said in ((_tamper(good, "sibling"), "INVALID"), ({**good, "block": 7}, "NOT FOUND"),
                      ({**good, "block": None}, "NOT FOUND")):
        f = tmp_path / "bad.json"
        f.write_text(json.dumps(bad))
        capsys.readouterr()
        assert run(L, tf, "cohort", "verify", str(f)) == 1
        assert capsys.readouterr().out.startswith(said)
    f.write_text(json.dumps(_tamper(good, "sibling")))
    with pytest.raises(SystemExit, match="refused: INVALID"):
        run(L, tf, "cohort", "revoke", str(f))


def test_a_proof_of_a_cohort_never_sealed_is_not_found(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    land(L, sk, mac, 1)
    assert run(L, tf, "cohort", "build", str(write_fps(tmp_path, FIVE[:4])), "--out", str(tmp_path / "b")) == 0
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(tmp_path / "b" / f"{FIVE[0]}.json")) == 1
    assert capsys.readouterr().out.startswith("NOT FOUND")
    with pytest.raises(SystemExit, match="refused: NOT FOUND"):
        run(L, tf, "cohort", "revoke", str(tmp_path / "b" / f"{FIVE[0]}.json"))


def test_a_root_sealed_as_another_kind_does_not_count(world, sk, mac, tmp_path, capsys):
    """Only a cert-cohort block seals a cohort: the same hash sealed as a revocation is not one."""
    L, trust, tf = world
    _, [p] = cohort.build([FIVE[0]], block=1)   # names the very block that holds its root
    pf = tmp_path / "p.json"; pf.write_text(cohort.proof_json(p))
    from aikiri_ledger.request import Request
    head = L.head()
    L.requests_dir.mkdir(parents=True, exist_ok=True)
    (L.requests_dir / "next.json").write_text(json.dumps(Request.unsigned(
        index=head.index + 1, prev_hash=head.hash, roots=[{"kind": "revocation", "sha256": p["root"]}],
        validator=head.validator)))
    land(L, sk, mac, 1)
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(pf)) == 1
    assert capsys.readouterr().out.startswith("NOT FOUND")
    with pytest.raises(SystemExit, match="already sealed as revocation"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, [FIVE[0]])))


def test_cohort_seal_push_commits_the_request_and_its_proofs_only(checkout, mac, monkeypatch, tmp_path_factory):
    L, tf, repo, remote = checkout
    monkeypatch.setattr(cli, "_approve", fake_approve(mac))
    (repo / "unrelated.txt").write_text("not staged, never pushed")
    elsewhere = tmp_path_factory.mktemp("issuer")
    assert run(L, tf, "cohort", "seal", str(write_fps(elsewhere, FIVE)), "--push") == 0
    pushed = _git(remote, "log", "-1", "--name-only", "--format=%s", "main").split()
    assert pushed[:3] == ["Request", "block", "1"]
    assert sorted(pushed[3:]) == sorted(["ledger/requests/next.json"] +
                                        [f"ledger/certs/{f}.json" for f in FIVE])
    sealed = json.loads(_git(remote, "show", "main:ledger/requests/next.json"))
    assert sealed["approval"]["device"] == "mac"
    assert sealed["roots"] == [{"kind": "cert-cohort", "sha256": cohort.root(FIVE)}]

    # The same line again: nothing new to commit, still exits 0.
    assert run(L, tf, "cohort", "seal", str(write_fps(elsewhere, FIVE)), "--push") == 0
    assert _git(remote, "rev-list", "--count", "main").strip() == "2"


def test_cohort_push_refuses_to_carry_other_staged_files(checkout, mac, monkeypatch, tmp_path_factory):
    L, tf, repo, remote = checkout
    monkeypatch.setattr(cli, "_approve", fake_approve(mac))
    (repo / "other.txt").write_text("x")
    _git(repo, "add", "other.txt")
    elsewhere = tmp_path_factory.mktemp("issuer")
    with pytest.raises(SystemExit, match="other files are staged"):
        run(L, tf, "cohort", "seal", str(write_fps(elsewhere, FIVE)), "--push")


def test_nothing_personal_in_the_vectors():
    """The vectors hold hashes of fake strings and fake records, and nothing else."""
    v = VECTORS
    assert set(v["inputs"]) == {f"test-cert-{i}" for i in range(1, 6)}
    for ex in v["records"]["examples"]:
        r = ex["record"]
        assert r["issuer"] == "Chiibitsu Labs" and r["instructor"] == "Test Instructor"
        assert r["holder"].startswith(("Test", "T\u00ebst")) and r["course"].startswith("Example Course")
        assert r.get("host", "Example Host") == "Example Host"


# --- found in review: each one refused cleanly, never a traceback or a wrong block --------

def test_a_stale_waiting_request_is_refused_and_names_no_block(world, sk, mac, tmp_path):
    """A request for block 1 still sits there after another block 1 landed: re-running the
    line must not write proofs naming that other block."""
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    payload = json.loads((L.requests_dir / "next.json").read_text())
    land(L, sk, mac, 1)                                   # block 1 is written; the head moved
    other = [fake(8), fake(9)]
    (L.requests_dir / "next.json").write_text(json.dumps(
        {**payload, "roots": [{"kind": "cert-cohort", "sha256": cohort.root(other)}]}))
    with pytest.raises(SystemExit, match="stale"):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, other)))
    assert not (certs(L) / f"{fake(8)}.json").exists()


@pytest.mark.parametrize("junk", [b"\xff\xfe", b"[" * 30000 + b"]" * 30000, b"1" * 5000,
                                  b'{"v":1,"v":1}', b"x" * 70000])
def test_junk_proof_files_are_invalid_not_a_crash(world, tmp_path, capsys, junk):
    L, trust, tf = world
    f = tmp_path / "junk.json"; f.write_bytes(junk)
    assert run(L, tf, "cohort", "verify", str(f)) == 1
    assert capsys.readouterr().out.startswith("INVALID")
    with pytest.raises(SystemExit, match="INVALID"):
        run(L, tf, "cohort", "revoke", str(f))
    assert cohort.verify_proof(junk) is False


def test_a_duplicate_key_is_refused_not_read_last_wins():
    _, [p] = cohort.build([FIVE[0]], block=3)
    text = cohort.proof_json(p).rstrip("\n")[:-1] + ',"block":9}'
    with pytest.raises(SchemaError, match="duplicate"):
        cohort.parse_proof(text)


def test_a_missing_or_unreadable_fingerprint_file_is_refused(world, tmp_path):
    L, trust, tf = world
    with pytest.raises(SystemExit, match="refused"):
        run(L, tf, "cohort", "seal", str(tmp_path / "nope.txt"))
    bad = tmp_path / "bad.txt"; bad.write_bytes(b"\xff\n")
    with pytest.raises(SystemExit, match="refused"):
        run(L, tf, "cohort", "build", str(bad), "--out", str(tmp_path / "o"))


def test_build_never_writes_inside_the_ledger(world, tmp_path):
    L, trust, tf = world
    before = snapshot(L)
    for inside in (L.root, L.requests_dir, L.root / "certs"):
        with pytest.raises(SystemExit, match="inside the ledger"):
            run(L, tf, "cohort", "build", str(write_fps(tmp_path, FIVE)), "--out", str(inside))
    assert snapshot(L) == before


def test_only_a_newline_separates_fingerprints():
    for sep in ("\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\x0b", "\x0c"):
        with pytest.raises(SchemaError, match="line 1"):
            cohort.read_fingerprints(FIVE[0] + sep + FIVE[1])
    assert cohort.read_fingerprints(FIVE[0] + "\r\n" + FIVE[1]) == FIVE[:2]


def test_revoke_refuses_on_a_ledger_copy_that_does_not_verify(world, sk, mac, tmp_path):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    land(L, sk, mac, 1)
    # No external trust file: no approval key registered, so every v2 block reads unapproved.
    with pytest.raises(SystemExit, match="refused: INVALID.*no trust file given"):
        cli.main(["--ledger", str(L.root), "cohort", "revoke", str(certs(L) / f"{FIVE[0]}.json")])
    assert not (L.requests_dir / "next.json").exists()


def test_proofs_are_written_whole(world, tmp_path, monkeypatch):
    """A write that dies part way leaves the old file, never half a proof."""
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    before = {f: (certs(L) / f"{f}.json").read_bytes() for f in FIVE}
    import os
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    (L.requests_dir / "next.json").unlink()
    with pytest.raises(OSError):
        run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE)))
    monkeypatch.setattr(os, "replace", real)
    for f in FIVE:
        assert (certs(L) / f"{f}.json").read_bytes() == before[f]   # still whole
    assert not [p for p in certs(L).iterdir() if p.name.endswith(".tmp")]


def test_revoke_push_reads_the_proof_after_the_pull(world, sk, mac, tmp_path, monkeypatch):
    """The proof is read from the checkout as the pull leaves it, never from before it."""
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    land(L, sk, mac, 1)
    target = certs(L) / f"{FIVE[0]}.json"
    upstream = target.read_bytes()
    target.unlink()                                   # not here until the pull brings it
    seen = []
    monkeypatch.setattr(cli, "_sync", lambda L: (seen.append("sync"), target.write_bytes(upstream)))
    monkeypatch.setattr(cli, "_push_request", lambda req, *a, **k: seen.append("push") or 0)
    assert run(L, tf, "cohort", "revoke", str(target), "--push") == 0
    assert seen == ["sync", "push"]
    assert json.loads((L.requests_dir / "next.json").read_text())["roots"] == [
        {"kind": "revocation", "sha256": FIVE[0]}]


def test_revoke_puts_a_missing_or_wrong_pointer_right(world, sk, mac, tmp_path, capsys):
    """Revoked on the ledger but not in ledger/certs/revoked/: the page would say valid."""
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    land(L, sk, mac, 1)
    proof = certs(L) / f"{FIVE[0]}.json"
    assert run(L, tf, "cohort", "revoke", str(proof)) == 0
    rblk = land(L, sk, mac, 2)
    mark = certs(L) / "revoked" / f"{FIVE[0]}.json"

    for damage in ("missing", "wrong block"):
        if damage == "missing":
            mark.unlink()
        else:
            mark.write_text(cohort.revoked_json(FIVE[0], 1))
        capsys.readouterr()
        assert run(L, tf, "cohort", "verify", str(proof)) == 1
        said = capsys.readouterr().out
        assert said.startswith("REVOKED") and "check page does not show this revocation" in said
        assert run(L, tf, "cohort", "revoke", str(proof)) == 0
        assert cohort.parse_revoked(mark.read_text()) == {"v": 1, "fingerprint": FIVE[0], "block": rblk.index}
        assert not (L.requests_dir / "next.json").exists()       # no second revocation block
        capsys.readouterr()
        assert run(L, tf, "cohort", "verify", str(proof)) == 1
        assert "check page does not show" not in capsys.readouterr().out


def test_a_proof_file_under_another_certificates_name_is_refused(world, sk, mac, tmp_path, capsys):
    L, trust, tf = world
    assert run(L, tf, "cohort", "seal", str(write_fps(tmp_path, FIVE))) == 0
    land(L, sk, mac, 1)
    (certs(L) / f"{FIVE[0]}.json").write_bytes((certs(L) / f"{FIVE[1]}.json").read_bytes())
    capsys.readouterr()
    assert run(L, tf, "cohort", "verify", str(certs(L) / f"{FIVE[0]}.json")) == 1
    assert capsys.readouterr().out.startswith("INVALID")
    with pytest.raises(SystemExit, match="proof of another certificate"):
        run(L, tf, "cohort", "revoke", str(certs(L) / f"{FIVE[0]}.json"))
    assert not (L.requests_dir / "next.json").exists()


def test_a_repaired_pointer_is_pushed_alone(checkout, sk, mac, monkeypatch, tmp_path_factory):
    L, tf, repo, remote = checkout
    monkeypatch.setattr(cli, "_approve", fake_approve(mac))
    elsewhere = tmp_path_factory.mktemp("issuer")
    assert run(L, tf, "cohort", "seal", str(write_fps(elsewhere, FIVE))) == 0
    land(L, sk, mac, 1)
    assert run(L, tf, "cohort", "revoke", str(certs(L) / f"{FIVE[0]}.json")) == 0
    land(L, sk, mac, 2)
    (certs(L) / "revoked" / f"{FIVE[0]}.json").unlink()
    _git(repo, "add", "-A"); _git(repo, "commit", "-q", "-m", "two blocks, no pointer"); _git(repo, "push", "-q")

    monkeypatch.setattr(cli, "_sync", lambda L: None)
    assert run(L, tf, "cohort", "revoke", str(certs(L) / f"{FIVE[0]}.json"), "--push") == 0
    pushed = _git(remote, "log", "-1", "--name-only", "--format=%s", "main").split("\n")
    assert pushed[0] == "Point the revoked certificate at block 2"
    assert [f for f in pushed[1:] if f] == [f"ledger/certs/revoked/{FIVE[0]}.json"]
