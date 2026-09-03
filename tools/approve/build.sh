#!/usr/bin/env bash
# Build and sign aikiri-approve.
#
# The signing is not optional. macOS refuses to store a Secure Enclave key for a
# process with no keychain access group, and an unsigned binary has none: the
# symptom is -34018 errSecMissingEntitlement at enroll time.
#
# Ad-hoc signing (`-s -`) is tried first because it needs no Apple account. If
# the enclave still refuses, sign with a real Apple Development identity, which
# a free Apple ID provides through Xcode:
#
#     security find-identity -v -p codesigning        # find its name
#     AIKIRI_SIGN_ID="Apple Development: you@example.com (XXXXXXXXXX)" ./build.sh
#
set -euo pipefail
cd "$(dirname "$0")/../.."

IDENTITY="${AIKIRI_SIGN_ID:--}"

swiftc -O -framework Security -framework LocalAuthentication \
    -o aikiri-approve tools/approve/AikiriApprove.swift

codesign --force --options runtime \
    --entitlements tools/approve/aikiri.entitlements \
    --sign "$IDENTITY" aikiri-approve

echo "built and signed with identity: $IDENTITY"
codesign -d --entitlements - aikiri-approve 2>&1 | grep -A2 keychain || true
echo
echo "next:  ./aikiri-approve enroll --device mac"
