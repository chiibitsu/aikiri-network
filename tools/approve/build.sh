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

GROUP_SUFFIX="com.chiibitsu.aikiri"

IDENTITY="${AIKIRI_SIGN_ID:-}"
if [ -z "$IDENTITY" ]; then
    IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null \
        | grep -E 'Apple Development|Developer ID Application' \
        | head -1 | sed -E 's/.*"(.*)"/\1/')
fi

if [ -z "$IDENTITY" ]; then
    cat >&2 <<'MSG'
No code signing identity found, and this tool cannot work without one.

  security find-identity -v -p codesigning

listed nothing usable. A free Apple ID gives you one:

  1. Open Xcode, Settings -> Accounts, add your Apple ID.
  2. Re-run the command above; an "Apple Development: ..." line appears.
  3. Re-run this script.

To use a specific identity:

  AIKIRI_SIGN_ID="Apple Development: you@example.com (XXXXXXXXXX)" tools/approve/build.sh
MSG
    exit 1
fi

# The Team ID lives in the certificate's OU field, and the access group must
# carry it as a prefix or the entitlement is ignored.
TEAM=$(security find-certificate -c "$IDENTITY" -p 2>/dev/null \
    | openssl x509 -noout -subject -nameopt multiline 2>/dev/null \
    | awk -F' = ' '/organizationalUnitName/ {print $2; exit}')

if [ -z "$TEAM" ]; then
    echo "could not read the Team ID out of '$IDENTITY'" >&2
    exit 1
fi

ENT=$(mktemp -t aikiri-entitlements)
trap 'rm -f "$ENT"' EXIT
cat > "$ENT" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>keychain-access-groups</key>
  <array>
    <string>${TEAM}.${GROUP_SUFFIX}</string>
  </array>
</dict>
</plist>
PLIST

swiftc -O -framework Security -framework LocalAuthentication \
    -o aikiri-approve tools/approve/AikiriApprove.swift

codesign --force --options runtime --entitlements "$ENT" \
    --sign "$IDENTITY" aikiri-approve

echo "identity:      $IDENTITY"
echo "team:          $TEAM"
echo "access group:  ${TEAM}.${GROUP_SUFFIX}"
echo
echo "next:  ./aikiri-approve enroll --device mac"
