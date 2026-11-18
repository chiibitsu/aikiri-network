# Human approval

## Why it exists

The first version of this ledger assumed a forged block would be caught by the
witnesses. That is wrong, and the error mattered enough to change the format.

An attacker who holds the validator key and the wallet key can sign a block and
call `anchor` on it. Base stamps whatever it is given. OpenTimestamps stamps
whatever it is given. Both witnesses then attest, correctly and permanently,
that the forgery existed at that moment. Witnessing proves time and order. It
does not prove consent, and both keys live in a CI runner.

So consent is a separate factor, held somewhere the runner cannot reach.

## What it is

**Today:** one P-256 key in a passphrase-encrypted file on Chii's Mac, made
with `aikiri-ledger approve-keygen`. It is never in CI and never in the
repository, and it signs only when she types the passphrase. `trust.json`
registers one device, `mac`. So the Mac is a single point of failure.

**The design it falls short of:** a non-exportable key inside the Secure Enclave
of her Mac and of her iPhone, each signature gated by Touch ID or Face ID, both
devices registered. macOS will not keep an enclave key for a command-line tool,
so that waits on an app. `docs/setup.md` §7 says why, what the file key still
delivers, and what it does not.

**The upgrade path:** enroll a second device, either the enclave app or another
machine with its own file key, and publish an updated trust anchor. Blocks the
file key already approved stay valid. Which device, and when, is Chii's call
(`docs/setup.md` §7).

## What is signed

    "aikiri-ledger/approval/v1\n" + canonical({
        index, nonce, prev_hash, roots, validator
    })

Canonical is the same rule the rest of the ledger uses: JSON, sorted keys,
compact, ASCII-escaped. The exact bytes are frozen in
`tests/vectors/v2_blocks.json` and reproduced independently in the Swift signer,
which builds the string by hand rather than trusting an encoder's key order.

Changing any field breaks the approval:

| field | what it stops |
|---|---|
| `index` | replaying an approval at a different height |
| `prev_hash` | approving a block onto a different history |
| `roots` | swapping what was sealed after she approved it |
| `nonce` | replaying the same approval twice |
| `validator` | a second validator key reusing her approval |

The approval sits inside the block's hashed bytes, so it cannot be stripped or
swapped without breaking both the block hash and the validator signature.

## Where the keys are pinned

In the trust anchor, beside the validator key, as `approval_keys`. A block whose
approval does not verify against a registered device is invalid. A device label
cannot borrow another device's trust: the label and the key must match the pair
that was registered.

The trust anchor is published outside this repository. Pins kept beside the
ledger prove nothing, because whoever can rewrite one can rewrite the other.

## The flow, per block

1. On her Mac, against the vault: `aikiri-ledger request <path> --kind journal --out request.json`.
   This hashes the file and writes the unsigned payload. The content never leaves
   the vault; only the hash travels.
2. `aikiri-ledger approve request.json`. The terminal prints what is about to be
   approved, then asks for the passphrase. The sealed request comes back with the
   approval. (`aikiri-approve sign` is the enclave signer this step was designed
   around; it cannot run as a command-line tool on macOS. See docs/setup.md §7.)
3. Push the sealed request to `ledger/requests/` on `main`. That push, and only
   that push, starts the block workflow.
4. The runner writes the block, anchors it on Base, stamps it on Bitcoin, commits
   the block and its proofs, and deletes the request. If the stamp fails, the block
   is still committed, and nightly stamps it.

The nightly ritual no longer writes blocks. It upgrades pending Bitcoin proofs,
stamps any block with no `.ots` yet, and re-verifies. Blocks wait for her. That is the intended cost.

## Losing a device

**Today, with one device registered,** losing the key file or its passphrase is
the "every device" case below: the chain freezes. `docs/setup.md` §6 says to back
up the file and remember the passphrase.

**One of several**, once a second device is enrolled. Another approves;
nothing stops. But the lost device's key is still registered and still valid, and rotation does not exist yet, so a device
that is lost rather than destroyed must be treated as a live credential in
someone else's hands. It is one of three factors — an attacker also needs the
validator key and the wallet key to produce a block — but it is no longer a
factor Chii controls. Remove it by publishing a new trust anchor without that
device, which every verifier will pick up; blocks already approved by it stay
valid, which is correct, because they were.

**Every device.** The chain freezes. No further block can ever be approved, and
under v2 rules there is no way to add a device, because the thing that would
authorise adding one is exactly what was lost. Everything already written stays
verifiable forever by anyone: verification needs only public keys, the two
witnesses, and the published trust anchor. The trail survives; it just stops.

**Biometric changes** apply to the enclave signer, once an app exists; the file
key has no biometry, only its passphrase. The enclave key is created with
`.biometryAny`, so adding a fingerprint or re-enrolling a face does not destroy it. `--strict-biometry`
switches to `.biometryCurrentSet`, which is stronger — a stolen unlocked device
with an added fingerprint cannot sign — but destroys the key on any enrolment
change. Until rotation exists, that is a way to lose a device by accident, so it
is not the default.

## The recovery path, not yet built

Rotation is deliberately unimplemented; designing it under time pressure after a
loss is how people build back doors. What it needs, when it is designed:

- A further registered factor whose loss is uncorrelated with the devices that
  travel with her. An offline key on paper in a safe is the obvious
  candidate, and it does not need an enclave, only a different failure mode.
- A rotation record sealed like everything else: a block whose root is the new
  device set, approved by a surviving factor, so the change is on the trail
  rather than in a settings page.
- A rule for verifiers reading old blocks: an approval valid when it was made
  stays valid. Rotation adds devices going forward; it never invalidates history.

Until then the honest statement is the one above: one device today, so losing it
freezes the chain; with more, any one approves and losing all of them freezes it;
and everything already sealed remains provable.
