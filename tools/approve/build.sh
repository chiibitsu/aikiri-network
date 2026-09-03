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

# Every lookup below ends in `|| true`. Without it, `set -e` plus a grep that
# matches nothing exits the script silently, which looks exactly like the script
# never running, and leaves a stale binary on disk to be killed later.
ALL=$(security find-identity -v -p codesigning 2>/dev/null || true)
echo "code signing identities on this Mac:"
echo "${ALL:-  (none)}"
echo

IDENTITY="${AIKIRI_SIGN_ID:-}"
if [ -z "$IDENTITY" ]; then
    # Prefer an Apple-issued identity; a self-signed one is a fallback.
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
TEAM="${AIKIRI_TEAM_ID:-}"
[ -n "$TEAM" ] || TEAM=$(security find-certificate -c "$IDENTITY" -p 2>/dev/null \
    | openssl x509 -noout -subject -nameopt multiline 2>/dev/null \
    | awk -F' = ' '/organizationalUnitName/ {print $2; exit}' || true)
# An Apple Development certificate carries the Team ID in its OU. If that read
# fails, pass it yourself: AIKIRI_TEAM_ID=XXXXXXXXXX tools/approve/build.sh

if [ -z "$TEAM" ]; then
    # A self-signed certificate has no Team ID. Try the bare group; macOS may
    # refuse the entitlement, which shows up as -34018 at enroll time. If it
    # does, an Apple-issued identity is the only way, and Xcode mints one free.
    echo "note: '$IDENTITY' carries no Team ID, so it is not Apple-issued." >&2
    echo "      Trying an unprefixed access group. If enroll reports -34018," >&2
    echo "      this certificate cannot carry the entitlement and you need an" >&2
    echo "      Apple Development identity (Xcode, Settings -> Accounts)." >&2
    GROUP="$GROUP_SUFFIX"
else
    GROUP="${TEAM}.${GROUP_SUFFIX}"
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
    <string>${GROUP}</string>
  </array>
</dict>
</plist>
PLIST

rm -f aikiri-approve   # a stale binary from a failed run must not be runnable

swiftc -O -framework Security -framework LocalAuthentication \
    -o aikiri-approve tools/approve/AikiriApprove.swift

# If codesign fails, the compiled binary must not survive: an unsigned one runs
# happily and then fails at enroll with -34018, which looks like an enclave
# problem rather than a signing problem.
if ! codesign --force --options runtime --entitlements "$ENT" \
        --sign "$IDENTITY" aikiri-approve; then
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

codesign -dv --entitlements - aikiri-approve 2>&1 | grep -E 'TeamIdentifier|keychain|Authority' || true

echo "identity:      $IDENTITY"
echo "access group:  ${GROUP}"
echo
echo "next:  ./aikiri-approve enroll --device mac"
