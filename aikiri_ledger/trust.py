"""Where the verifier's expectations come from.

Values kept in this repository are not a trust anchor. Whoever can rewrite the
ledger can rewrite the pins beside it, and a verifier that checks a file
against its neighbour proves nothing. So the pins ship here as a convenience
and are labelled `repo`: a verification that rests on them can never report
more than VALID LOCALLY.

An anchor is a trust file supplied from outside the repository, ideally signed
by one of the registered approval devices. Anyone can hold a copy; that is the
point. Publish it beside the receipt, not inside the thing being checked.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .approval import ApprovalKey, trust_message, verify_signature
from .canonical import exact_int, hex64, loads_strict, plain_str, strict
from .errors import SchemaError, TrustError

TRUST_FIELDS = ("v", "chainId", "contract", "owner", "code_keccak", "genesis_hash",
                "validator", "approval_keys", "legacy")
TRUST_VERSION = 1

# Convenience only. Not an anchor. See the module docstring.
REPO_DEFAULTS = {
    "v": 1,
    "chainId": 8453,
    "contract": "0x15eFF43a5CFA703215fAa943D42168aF5a7A6a9e",
    "owner": "0xB76B710cDa104DB946A619B1450E02D44cB97194",
    "code_keccak": None,
    "genesis_hash": "73715608c05be3f134036de0f5a1606b348098e2bebf34c8102680be08650ea8",
    "validator": "d16ab31e87e945b56a8a4e48905fbe883330405773a92d2ece8ddcb112ec63ba",
    "approval_keys": [],
    "legacy": {
        "0": "73715608c05be3f134036de0f5a1606b348098e2bebf34c8102680be08650ea8",
        "1": "69e7256e4f12a359863fbb1408a8c41c5643cfa13909b6e95104e1880fbaed5b",
    },
}


@dataclass
class Trust:
    chain_id: int
    contract: str | None
    owner: str | None
    code_keccak: str | None
    genesis_hash: str | None
    validator: str | None
    approval_keys: list = field(default_factory=list)
    legacy: dict = field(default_factory=dict)
    source: str = "repo"

    @property
    def is_external(self) -> bool:
        return self.source.startswith("external")

    @property
    def signed(self) -> bool:
        return self.source == "external-signed"

    def describe(self) -> str:
        return {"repo": "pins read from this repository — NOT an independent trust anchor",
                "external-unsigned": "external trust file, unsigned",
                "external-signed": "external trust file, signed by a registered device",
                }.get(self.source, self.source)

    # ---- construction ----
    @classmethod
    def from_repo_defaults(cls) -> "Trust":
        return cls._from_body(REPO_DEFAULTS, "repo")

    @staticmethod
    def _inside_this_repo(path: Path) -> bool:
        """A trust file that lives in the repository it is checking is not an anchor,
        however it is passed on the command line."""
        try:
            path = path.resolve()
        except OSError:
            return False
        here = Path.cwd().resolve()
        root = next((d for d in [here, *here.parents] if (d / ".git").exists()), None)
        if root is None:
            return False
        return root in path.parents or path.parent == root

    @classmethod
    def load(cls, path: str | Path) -> "Trust":
        path = Path(path)
        raw = loads_strict(path.read_text())
        if not isinstance(raw, dict) or "trust" not in raw:
            raise TrustError("trust file: expected {\"trust\": {...}} with an optional \"sig\"")
        extra = set(raw) - {"trust", "sig", "note"}  # `note` is for humans, ignored here
        if extra:
            raise TrustError(f"trust file: unknown field(s) {sorted(extra)}")
        body = raw["trust"]
        trust = cls._from_body(body, "external-unsigned")
        if "sig" in raw:
            sig = raw["sig"]
            try:
                strict(sig, ("device", "pubkey", "sig"), "trust.sig")
            except SchemaError as e:
                raise TrustError(str(e)) from e
            known = {k.device: k.pubkey for k in trust.approval_keys}
            if sig["device"] not in known or known[sig["device"]] != sig["pubkey"]:
                raise TrustError(f"trust file signed by {sig['device']!r}, which is not one of "
                                 f"the approval keys it declares")
            if not verify_signature(sig["pubkey"], trust_message(body), sig["sig"]):
                raise TrustError("trust file signature does not cover its contents")
            trust.source = "external-signed"
        if cls._inside_this_repo(path):
            trust.source = "repo"
        return trust

    @classmethod
    def _from_body(cls, body, source: str) -> "Trust":
        try:
            strict(body, TRUST_FIELDS, "trust")
            if exact_int(body["v"], "trust.v") != TRUST_VERSION:
                raise SchemaError(f"trust.v: expected {TRUST_VERSION}")
            keys = []
            if not isinstance(body["approval_keys"], list):
                raise SchemaError("trust.approval_keys: expected a list")
            for i, k in enumerate(body["approval_keys"]):
                strict(k, ("device", "pubkey"), f"trust.approval_keys[{i}]")
                keys.append(ApprovalKey(plain_str(k["device"], "device"), k["pubkey"]))
            if len({k.device for k in keys}) != len(keys):
                raise SchemaError("trust.approval_keys: device labels must be unique")
            if not isinstance(body["legacy"], dict):
                raise SchemaError("trust.legacy: expected an object")
            legacy = {exact_int(int(i), "trust.legacy key"): hex64(h, "trust.legacy value")
                      for i, h in body["legacy"].items()}
        except SchemaError as e:
            raise TrustError(str(e)) from e
        return cls(chain_id=exact_int(body["chainId"], "trust.chainId"),
                   contract=body["contract"], owner=body["owner"],
                   code_keccak=body["code_keccak"], genesis_hash=body["genesis_hash"],
                   validator=body["validator"], approval_keys=keys, legacy=legacy,
                   source=source)

    def body(self) -> dict:
        return {"v": TRUST_VERSION, "chainId": self.chain_id, "contract": self.contract,
                "owner": self.owner, "code_keccak": self.code_keccak,
                "genesis_hash": self.genesis_hash, "validator": self.validator,
                "approval_keys": [{"device": k.device, "pubkey": k.pubkey}
                                  for k in self.approval_keys],
                "legacy": {str(i): h for i, h in sorted(self.legacy.items())}}

    def write(self, path: str | Path, approver=None) -> Path:
        doc = {"trust": self.body()}
        if approver is not None:
            doc["sig"] = approver.sign_trust(doc["trust"])
        p = Path(path)
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        return p
