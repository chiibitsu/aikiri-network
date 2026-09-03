"""An approval key held in a file, encrypted with a passphrase.

The Secure Enclave is the better home for this key, and on macOS it is out of
reach from a command-line tool: the keychain will not store an enclave key
without a `keychain-access-groups` entitlement, that entitlement needs a
provisioning profile, and only an app bundle can carry one. Until an app exists,
this is the approval factor.

What it still gives, which is the thing that was actually ruled on: possession of
the validator key and the wallet key is not consent. Both of those live in a CI
runner. This key does not, and it cannot be used without a passphrase typed by
hand.

What it does not give, and the enclave would: resistance to malware already
running on Chii's Mac. A keylogger plus a copy of the file is enough. That is a
smaller threat than a compromised runner, and it is the honest limit of this.

The key is P-256, exactly like an enclave key, so a block approved by this signer
and a block approved by a future enclave device are indistinguishable to the
verifier. Migrating later means enrolling the enclave as another device, not
changing the format.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .approval import SoftwareApprover
from .canonical import canonical_bytes, exact_int, hexstr, loads_strict, plain_str, strict
from .errors import SchemaError

KEYFILE_FIELDS = ("v", "device", "kdf", "nonce", "ciphertext", "pubkey")
KDF_FIELDS = ("name", "n", "r", "p", "salt")
VERSION = 1

# ~128 MB and about a second. The file is the only thing an attacker gets, so the
# passphrase is the whole defence and the KDF should hurt.
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1


class BadPassphrase(ValueError):
    """The passphrase did not decrypt the key."""


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not passphrase:
        raise ValueError("a passphrase is required")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def default_path(device: str) -> Path:
    return Path(os.path.expanduser(f"~/.aikiri/approval-{device}.key"))


def create(path: str | Path, device: str, passphrase: str) -> str:
    """Write a new encrypted approval key. Returns the public key, hex."""
    device = plain_str(device, "device")
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"{p} already exists; refusing to overwrite an approval key")

    sk = ec.generate_private_key(ec.SECP256R1())
    raw = sk.private_bytes(serialization.Encoding.DER,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    pub = sk.public_key().public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.UncompressedPoint).hex()

    # The public key and device are authenticated, so a file whose pubkey has been
    # swapped will not decrypt rather than silently signing with the wrong key.
    aad = canonical_bytes({"device": device, "pubkey": pub, "v": VERSION})
    doc = {"v": VERSION, "device": device, "pubkey": pub,
           "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                   "salt": salt.hex()},
           "nonce": nonce.hex(),
           "ciphertext": AESGCM(key).encrypt(nonce, raw, aad).hex()}

    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    return pub


def load(path: str | Path, passphrase: str) -> SoftwareApprover:
    """Decrypt the key and return a signer with the same interface an enclave
    device would have."""
    doc = loads_strict(Path(path).read_text())
    strict(doc, KEYFILE_FIELDS, "approval key file")
    if exact_int(doc["v"], "approval key file.v") != VERSION:
        raise SchemaError(f"approval key file.v: expected {VERSION}")
    device = plain_str(doc["device"], "approval key file.device")
    pub = hexstr(doc["pubkey"], "approval key file.pubkey")
    kdf = strict(doc["kdf"], KDF_FIELDS, "approval key file.kdf")
    if kdf["name"] != "scrypt":
        raise SchemaError(f"approval key file.kdf.name: unsupported {kdf['name']!r}")
    n, r, p_ = (exact_int(kdf[k], f"kdf.{k}") for k in ("n", "r", "p"))
    if n < (1 << 14) or n & (n - 1):
        raise SchemaError("approval key file.kdf.n: must be a power of two, at least 2^14")

    key = _derive(passphrase, bytes.fromhex(hexstr(kdf["salt"], "kdf.salt")), n, r, p_)
    aad = canonical_bytes({"device": device, "pubkey": pub, "v": VERSION})
    try:
        raw = AESGCM(key).decrypt(bytes.fromhex(hexstr(doc["nonce"], "nonce")),
                                  bytes.fromhex(hexstr(doc["ciphertext"], "ciphertext")), aad)
    except InvalidTag as e:
        raise BadPassphrase("wrong passphrase, or the key file has been altered") from e

    sk = serialization.load_der_private_key(raw, password=None)
    approver = SoftwareApprover(sk, device)
    if approver.public_key_hex != pub:
        raise BadPassphrase("the key file's public key does not match the key inside it")
    return approver
