"""Human approval, held in the Apple Secure Enclave.

Possession of the automated keys is not Chii's consent. The validator key
signs blocks and the wallet key anchors them; an attacker holding both can
forge a block and make the witnesses stamp the forgery. So every block also
carries an approval produced on a registered device, gated by Touch ID or
Face ID, with a key that cannot leave that device's enclave.

The approval signs index, prev_hash, roots, nonce and validator. Change any
one of them and the approval no longer verifies.

Key and signature shapes are what the Secure Enclave emits:
  public key  P-256, X9.62 uncompressed (0x04 || X || Y), 65 bytes
  signature   ECDSA over SHA-256, DER encoded
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

from .canonical import (APPROVAL_DOMAIN_V1, TRUST_DOMAIN_V1, canonical_bytes, hexstr,
                        plain_str, strict)
from .errors import SchemaError

APPROVAL_FIELDS = ("device", "pubkey", "sig")


@dataclass(frozen=True)
class ApprovalKey:
    device: str
    pubkey: str

    def __post_init__(self):
        plain_str(self.device, "approval key device")
        _load_pubkey(self.pubkey)


def _load_pubkey(pubkey_hex: str):
    hexstr(pubkey_hex, "approval pubkey")
    raw = bytes.fromhex(pubkey_hex)
    if len(raw) != 65 or raw[0] != 0x04:
        raise SchemaError("approval pubkey: expected an uncompressed P-256 point (0x04 || X || Y)")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as e:
        raise SchemaError(f"approval pubkey: not a valid P-256 point: {e}") from e


def approval_message(*, index: int, prev_hash: str, roots: list, nonce: str, validator: str) -> bytes:
    """The exact bytes a device signs. Frozen in tests/vectors/."""
    return APPROVAL_DOMAIN_V1 + canonical_bytes(
        {"index": index, "nonce": nonce, "prev_hash": prev_hash,
         "roots": roots, "validator": validator})


def trust_message(body: dict) -> bytes:
    return TRUST_DOMAIN_V1 + canonical_bytes(body)


def verify_signature(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        _load_pubkey(pubkey_hex).verify(bytes.fromhex(hexstr(sig_hex, "signature")),
                                        message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, SchemaError):
        return False


def verify_approval(approval, *, index: int, prev_hash: str, roots: list, nonce: str,
                    validator: str, registered: list[ApprovalKey] | None) -> tuple[bool, str]:
    """`registered=None` checks only that the signature binds the payload. Callers
    that decide whether a block is valid must always pass the registered devices."""
    try:
        strict(approval, APPROVAL_FIELDS, "approval")
        device = plain_str(approval["device"], "approval device")
        pubkey = approval["pubkey"]
        _load_pubkey(pubkey)
        hexstr(approval["sig"], "approval sig")
    except SchemaError as e:
        return False, str(e)

    if registered is not None:
        known = {k.device: k.pubkey for k in registered}
        if device not in known:
            return False, f"approval by {device!r}: not a registered device"
        if known[device] != pubkey:
            return False, (f"approval by {device!r}: device label does not match the "
                           f"key registered for it")

    msg = approval_message(index=index, prev_hash=prev_hash, roots=roots,
                           nonce=nonce, validator=validator)
    if not verify_signature(pubkey, msg, approval["sig"]):
        return False, f"approval by {device!r}: signature does not cover this block"
    return True, "ok"


class SoftwareApprover:
    """A stand-in for a Secure Enclave device, for tests and for a dry run before
    the real devices are enrolled. It produces the same key and signature shapes.
    It is not a substitute for the enclave: this key sits in memory."""

    def __init__(self, private_key, device: str):
        self._sk = private_key
        self.device = plain_str(device, "device")

    @classmethod
    def from_seed(cls, seed: bytes, device: str) -> "SoftwareApprover":
        # Order of the P-256 group; the seed is reduced into [1, n-1].
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        value = (int.from_bytes(seed, "big") % (n - 1)) + 1
        return cls(ec.derive_private_key(value, ec.SECP256R1()), device)

    @property
    def public_key_hex(self) -> str:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()

    def _sign(self, message: bytes) -> str:
        return self._sk.sign(message, ec.ECDSA(hashes.SHA256())).hex()

    def approve(self, *, index: int, prev_hash: str, roots: list, nonce: str,
                validator: str) -> dict:
        msg = approval_message(index=index, prev_hash=prev_hash, roots=roots,
                               nonce=nonce, validator=validator)
        return {"device": self.device, "pubkey": self.public_key_hex, "sig": self._sign(msg)}

    def sign_trust(self, body: dict) -> dict:
        return {"device": self.device, "pubkey": self.public_key_hex,
                "sig": self._sign(trust_message(body))}

    def as_key(self) -> ApprovalKey:
        return ApprovalKey(self.device, self.public_key_hex)
