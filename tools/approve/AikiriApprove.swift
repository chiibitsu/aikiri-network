// aikiri-approve ~ Secure Enclave approval. NOT USABLE AS A COMMAND-LINE TOOL.
//
// This compiles and signs, and then macOS refuses to store the key:
//   unsigned                        -> -34018 errSecMissingEntitlement
//   ad-hoc signed with entitlements -> the kernel kills the process at launch
//   Apple Development signed, no entitlement, login keychain -> -34018
//
// The keychain will not keep a Secure Enclave key for a process without a
// `keychain-access-groups` entitlement; that entitlement is restricted and is
// only honoured for a bundle carrying a provisioning profile; and only an app
// bundle can carry one. A `swiftc` binary cannot. Finishing this means an Xcode
// app target, which is docs/setup.md §7 route 2.
//
// The working approval signer today is `aikiri-ledger approve`, a P-256 key held
// in a passphrase-encrypted file (aikiri_ledger/softkey.py). It produces the same
// key and signature shapes, so this file stays as the starting point for the app.
//
// A P-256 key is created inside the Secure Enclave and never leaves it. There is
// no export, no backup, no copy in a password manager: the private key is not
// representable outside the chip. Every signature is gated by Touch ID or Face ID.
//
// This is what makes possession of the automated keys insufficient. An attacker
// holding the validator key and the wallet key can sign a block and make Base
// stamp it, but the block will carry no approval, and the verifier refuses it.
//
// Build (macOS):
//     swiftc -O -framework Security -framework LocalAuthentication \
//         -o aikiri-approve AikiriApprove.swift
//
// Use:
//     aikiri-approve enroll --device mac
//     aikiri-approve pubkey --device mac
//     aikiri-approve sign request.json
//
// The bytes signed here must match aikiri_ledger/approval.py exactly. They are
// built by hand below rather than through a JSON encoder, because the encoder's
// key order and escaping are not part of any contract and this is.

import Foundation
import Security
import LocalAuthentication

let TAG_PREFIX = "com.chiibitsu.aikiri.approval."
let APPROVAL_DOMAIN = "aikiri-ledger/approval/v1\n"

// MARK: - errors

struct Fail: Error, CustomStringConvertible {
    let description: String
    init(_ m: String) { description = m }
}

func die(_ message: String) -> Never {
    FileHandle.standardError.write(("aikiri-approve: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

// MARK: - keys

func tag(for device: String) -> Data {
    (TAG_PREFIX + device).data(using: .utf8)!
}

/// Create the device's approval key inside the Secure Enclave.
///
/// `.biometryAny` is the default rather than `.biometryCurrentSet`: the stricter
/// flag destroys the key when a fingerprint or face is added, and until a rotation
/// protocol exists a destroyed key is a device permanently lost. Pass
/// --strict-biometry to opt into the stricter behaviour once rotation exists.
func createKey(device: String, strictBiometry: Bool) throws -> SecKey {
    var error: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = strictBiometry
        ? [.privateKeyUsage, .biometryCurrentSet]
        : [.privateKeyUsage, .biometryAny]
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        flags,
        &error
    ) else {
        throw Fail("could not build an access control: \(error!.takeRetainedValue())")
    }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag(for: device),
            kSecAttrAccessControl as String: access,
        ],
    ]
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let e = error!.takeRetainedValue()
        if "\(e)".contains("34018") {
            throw Fail("""
                the keychain refused to store the key (-34018).
                The binary must carry a valid Apple code signature. Build it with
                tools/approve/build.sh, which signs it, and check that
                    security find-identity -v -p codesigning
                reports a valid identity.
                """)
        }
        throw Fail("the Secure Enclave refused to create a key: \(e)")
    }
    return key
}

func loadKey(device: String, reason: String) throws -> SecKey {
    let context = LAContext()
    context.localizedReason = reason
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: tag(for: device),
        kSecReturnRef as String: true,
        kSecUseAuthenticationContext as String: context,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let key = item else {
        throw Fail("no approval key for device '\(device)' on this machine "
                   + "(OSStatus \(status)). Run: aikiri-approve enroll --device \(device)")
    }
    return (key as! SecKey)
}

/// X9.62 uncompressed point, 65 bytes: 0x04 || X || Y. What the verifier pins.
func publicKeyHex(_ privateKey: SecKey) throws -> String {
    guard let pub = SecKeyCopyPublicKey(privateKey) else {
        throw Fail("could not derive the public key")
    }
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
        throw Fail("could not export the public key: \(error!.takeRetainedValue())")
    }
    return data.map { String(format: "%02x", $0) }.joined()
}

/// ECDSA over SHA-256, DER encoded. The enclave hashes the message itself.
func sign(_ message: Data, with key: SecKey) throws -> String {
    var error: Unmanaged<CFError>?
    guard let sig = SecKeyCreateSignature(
        key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error
    ) as Data? else {
        throw Fail("signing was refused: \(error!.takeRetainedValue())")
    }
    return sig.map { String(format: "%02x", $0) }.joined()
}

// MARK: - the exact bytes

func jsonString(_ s: String) throws -> String {
    // Every field in a request is hex or a known kind. Anything else is a bug
    // upstream or an attempt to smuggle content, and is refused here too.
    for scalar in s.unicodeScalars where scalar.value < 0x20 || scalar.value > 0x7E
        || scalar == "\"" || scalar == "\\" {
        throw Fail("field contains a character that does not belong in a request: \(s)")
    }
    return "\"" + s + "\""
}

/// aikiri_ledger.approval.approval_message, byte for byte.
/// Keys sorted: index, nonce, prev_hash, roots, validator. Roots: kind, sha256.
func approvalMessage(index: Int, prevHash: String, roots: [[String: String]],
                     nonce: String, validator: String) throws -> Data {
    var rootParts: [String] = []
    for r in roots {
        guard let kind = r["kind"], let sha = r["sha256"], r.count == 2 else {
            throw Fail("a root must have exactly kind and sha256")
        }
        rootParts.append("{\"kind\":" + (try jsonString(kind))
                         + ",\"sha256\":" + (try jsonString(sha)) + "}")
    }
    let body = "{\"index\":\(index)"
        + ",\"nonce\":" + (try jsonString(nonce))
        + ",\"prev_hash\":" + (try jsonString(prevHash))
        + ",\"roots\":[" + rootParts.joined(separator: ",") + "]"
        + ",\"validator\":" + (try jsonString(validator)) + "}"
    return (APPROVAL_DOMAIN + body).data(using: .utf8)!
}

// MARK: - commands

func argValue(_ name: String, _ args: [String]) -> String? {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    return args[i + 1]
}

func cmdEnroll(_ args: [String]) throws {
    guard let device = argValue("--device", args) else { die("enroll needs --device <name>") }
    let key = try createKey(device: device, strictBiometry: args.contains("--strict-biometry"))
    let pub = try publicKeyHex(key)
    print("device:  \(device)")
    print("pubkey:  \(pub)")
    print("")
    print("Register it, then publish the trust file outside the ledger repository:")
    print("  aikiri-ledger enroll --device \(device) --pubkey \(pub)")
}

func cmdPubkey(_ args: [String]) throws {
    guard let device = argValue("--device", args) else { die("pubkey needs --device <name>") }
    let key = try loadKey(device: device, reason: "Read the Aikiri approval key")
    print(try publicKeyHex(key))
}

func cmdSign(_ args: [String]) throws {
    guard let path = args.first(where: { !$0.hasPrefix("--") }) else {
        die("sign needs a request file")
    }
    let url = URL(fileURLWithPath: path)
    let raw = try Data(contentsOf: url)
    guard let obj = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
          let index = obj["index"] as? Int,
          let prevHash = obj["prev_hash"] as? String,
          let nonce = obj["nonce"] as? String,
          let validator = obj["validator"] as? String,
          let roots = obj["roots"] as? [[String: String]] else {
        die("\(path) is not a request payload")
    }
    guard roots.count == 1 else { die("a request carries exactly one root") }
    let device = argValue("--device", args) ?? "mac"

    // Show her what she is approving, before the sensor.
    print("Approve block \(index) of the Aikiri Network")
    print("  previous  \(prevHash)")
    print("  \(roots[0]["kind"] ?? "?")   \(roots[0]["sha256"] ?? "?")")
    print("  nonce     \(nonce)")
    print("  validator \(validator)")
    print("")

    let key = try loadKey(device: device,
                          reason: "Approve block \(index) of the Aikiri Network")
    let message = try approvalMessage(index: index, prevHash: prevHash, roots: roots,
                                      nonce: nonce, validator: validator)
    let sig = try sign(message, with: key)
    let pub = try publicKeyHex(key)

    var sealed = obj
    sealed["approval"] = ["device": device, "pubkey": pub, "sig": sig]
    let out = try JSONSerialization.data(withJSONObject: sealed,
                                         options: [.sortedKeys, .prettyPrinted,
                                                   .withoutEscapingSlashes])
    let outPath = argValue("--out", args) ?? path
    try (out + "\n".data(using: .utf8)!).write(to: URL(fileURLWithPath: outPath))
    print("approved by \(device); sealed request written to \(outPath)")
}

// MARK: - main

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    print("""
    aikiri-approve ~ Secure Enclave approval for the Aikiri Network

      enroll --device <name> [--strict-biometry]   create this device's key
      pubkey --device <name>                       print its public key
      sign <request.json> [--device <name>] [--out <path>]

    The private key is created in the Secure Enclave and cannot leave it.
    """)
    exit(0)
}

do {
    switch command {
    case "enroll": try cmdEnroll(Array(args.dropFirst()))
    case "pubkey": try cmdPubkey(Array(args.dropFirst()))
    case "sign": try cmdSign(Array(args.dropFirst()))
    default: die("unknown command '\(command)'")
    }
} catch {
    die("\(error)")
}
