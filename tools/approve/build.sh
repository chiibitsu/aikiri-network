#!/usr/bin/env bash
# Build and sign aikiri-approve.
#
# macOS will not store a Secure Enclave key for a process that has no keychain
# access group, and it only honours that entitlement when the group is prefixed
# by the Team ID of a real signing certificate. So:
#
#   unsigned            -> enroll fails with -34018 errSecMissingEntitlement
#   ad-hoc signed (-s -) -> the kernel kills the process at launch
#   signed with an Apple Development identity -> works
#
# A free Apple ID provides that identity: open Xcode once, Settings -> Accounts,
# add your Apple ID, and it appears. Then run this script.
set -euo pipefail
cd "$(dirname "$0")/../.."

IDENTITY="${AIKIRI_SIGN_ID:-}"
ALL=$(security find-identity -v -p codesigning 2>/dev/null || true)
echo "code signing identities on this Mac:"
echo "${ALL:-  (none)}"
echo

if [ -z "$IDENTITY" ]; then
    IDENTITY=$(printf '%s\n' "$ALL" \
        | grep -E 'Apple Development|Apple Distribution|Developer ID Application' \
        | head -1 | sed -E 's/.*"(.*)"/\1/' || true)
fi
if [ -z "$IDENTITY" ]; then
    IDENTITY=$(printf '%s\n' "$ALL" \
        | sed -nE 's/^ *[0-9]+\) [0-9A-F]+ "(.*)"$/\1/p' | head -1 || true)
fi

if [ -z "$IDENTITY" ]; then
    cat >&2 <<'MSG'
No valid code signing identity, and the Secure Enclave will not keep a key for
an unsigned binary.

  security find-identity -v -p codesigning

If that says 0 valid identities but Xcode shows a certificate, the Apple
intermediate is missing and the chain cannot be built. Install it:

  cd ~/Downloads && curl -sSLO https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
  security import ~/Downloads/AppleWWDRCAG3.cer -k ~/Library/Keychains/login.keychain-db
MSG
    exit 1
fi

rm -f aikiri-approve   # a stale binary from a failed run must not be runnable

swiftc -O -framework Security -framework LocalAuthentication \
    -o aikiri-approve tools/approve/AikiriApprove.swift

# If codesign fails, the compiled binary must not survive: an unsigned one runs
# happily and then fails at enroll with -34018, which looks like an enclave
# problem rather than a signing problem.
# Signed with no entitlements at all. keychain-access-groups is a restricted
# entitlement: macOS only honours it for a bundle carrying a provisioning
# profile, and kills a plain command-line binary that claims it. A valid Apple
# signature by itself is enough for the login keychain to keep the key.
if ! codesign --force --sign "$IDENTITY" aikiri-approve; then
    rm -f aikiri-approve
    cat >&2 <<'MSG'

codesign failed, so no binary was produced.

"unable to build chain to self-signed root" means the Apple intermediate
certificate is missing, and your certificate cannot be traced to Apple's root.
Install it, then run this script again:

    cd ~/Downloads && curl -sSLO https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
    open AppleWWDRCAG3.cer

    security find-identity -v -p codesigning     # should now say 1 valid identity
MSG
    exit 1
fi

codesign -dv aikiri-approve 2>&1 | grep -E 'TeamIdentifier|Authority=Apple' || true

echo "identity:      $IDENTITY"
echo
echo "next:  ./aikiri-approve enroll --device mac"
