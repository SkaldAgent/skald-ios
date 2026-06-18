//
//  CryptoConstants.swift
//  Skald
//
//  Domain constants and shared utilities for the Skald crypto layer.
//  See docs/../crypto.md §1 and §5 (encoding rules) for normative reference.
//
//  This file is compiled into BOTH targets:
//   - Skald (app)
//   - NotificationServiceExtension
//
//  Keep imports restricted to Apple frameworks that are available in an
//  app-extension process (CryptoKit, Foundation, Security, os). Do NOT import
//  UIKit / UserNotifications / AVFoundation here.
//

import CryptoKit
import Foundation
import Security
import os

// MARK: - Domain constants (crypto.md §1)

/// Normative constants for the Skald cryptographic protocol.
///
/// All `Data` constants are stored as raw bytes (UTF-8 of the string). The
/// direction tags are 4-byte big-endian values that prefix the AEAD nonce
/// (see `CryptoEngine.makeNonce`).
enum CryptoConstants {

    /// HKDF salt used when deriving the X25519/Ed25519 keypair from the seed
    /// (crypto.md §3).
    static let kdfSalt: Data = Data("skald-kdf-v1".utf8)

    /// HKDF info for the X25519 branch.
    static let kdfInfoX25519: Data = Data("x25519".utf8)

    /// HKDF info for the Ed25519 branch.
    static let kdfInfoEd25519: Data = Data("ed25519".utf8)

    /// HKDF salt for deriving the AEAD key from the ECDH shared secret
    /// (crypto.md §5).
    static let sessionSalt: Data = Data("skald-session-v1".utf8)

    /// HKDF info for the AEAD key derivation.
    static let sessionInfo: Data = Data("aes-256-gcm".utf8)

    /// Domain separator for the namespace_id derivation (crypto.md §7).
    static let namespaceDomain: Data = Data("skald-namespace-v1".utf8)

    /// Domain separator for the relay auth challenge (crypto.md §8).
    static let authDomain: Data = Data("skald-relay-auth-v1".utf8)

    /// Direction prefix for the nonce: agent → client.
    static let nonceDirAgentToClient: [UInt8] = [0x00, 0x00, 0x00, 0x01]

    /// Direction prefix for the nonce: client → agent.
    static let nonceDirClientToAgent: [UInt8] = [0x00, 0x00, 0x00, 0x02]

    /// V2 framing version byte (v2/framing.md §1).
    /// Today always 1. An unknown version → the receiver discards with log.
    static let framingVersion: UInt8 = 0x01

    /// V2 framing `comp = 0x00`: no compression. Use this for every outgoing
    /// payload (we only send small JSON envelopes; agent may send us compressed
    /// `inbox_update` snapshots — we MUST be able to receive `comp=0x01`).
    static let compNone: UInt8 = 0x00

    /// V2 framing `comp = 0x01`: zlib / DEFLATE. The iOS Compression framework
    /// exposes this as `COMPRESSION_ZLIB`.
    static let compZlib: UInt8 = 0x01
}

// MARK: - SkaldError

/// The single error type thrown by the Core layer.
///
/// All public Core APIs throw `SkaldError` (or rethrow wrapped in one).
/// `localizedDescription` does NOT include sensitive material (plaintext,
/// keys, nonces); it only exposes a short category suitable for logging.
enum SkaldError: Error, LocalizedError, Equatable {
    /// A key was malformed (wrong length, bad point, etc.).
    case invalidKey
    /// AES-GCM authentication failed (wrong key, wrong AAD, wrong nonce,
    /// tampered ciphertext).  We never distinguish the cause in the user
    /// message — per crypto.md §12.
    case decryptionFailed
    /// A nonce was rejected because it was the wrong size / direction.
    case invalidNonce
    /// Anti-replay rejection: incoming counter `<=` last-seen counter.
    case counterRegression
    /// A signature failed verification.
    case invalidSignature
    /// A QR payload was malformed (wrong `v`, bad hex, wrong field length).
    case invalidQRPayload
    /// A payload envelope was decoded but its `kind` is unknown or invalid.
    case invalidPayload
    /// A Keychain operation returned a non-zero OSStatus.
    case keychainError(OSStatus)
    /// A relay-level error reported by the server (`code`/`message`).
    case relayError(String)
    /// A transport-level error (URLSession, WS, timeout, etc.).
    case networkError(String)

    var errorDescription: String? {
        switch self {
        case .invalidKey:           return "Invalid key material"
        case .decryptionFailed:      return "Decryption failed"
        case .invalidNonce:          return "Invalid nonce"
        case .counterRegression:     return "Counter regression detected"
        case .invalidSignature:      return "Invalid signature"
        case .invalidQRPayload:      return "Invalid QR payload"
        case .invalidPayload:        return "Invalid payload"
        case .keychainError(let s):  return "Keychain error (OSStatus \(s))"
        case .relayError(let m):     return "Relay error: \(m)"
        case .networkError(let m):   return "Network error: \(m)"
        }
    }

    /// Equality considers only the case and the associated scalar (status code
    /// for `.keychainError`, raw string for `.relayError`/`.networkError`).
    /// `LocalizedError` does not conform to `Equatable` so we provide our own.
    static func == (lhs: SkaldError, rhs: SkaldError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidKey, .invalidKey),
             (.decryptionFailed, .decryptionFailed),
             (.invalidNonce, .invalidNonce),
             (.counterRegression, .counterRegression),
             (.invalidSignature, .invalidSignature),
             (.invalidQRPayload, .invalidQRPayload),
             (.invalidPayload, .invalidPayload):
            return true
        case let (.keychainError(a), .keychainError(b)):
            return a == b
        case let (.relayError(a), .relayError(b)):
            return a == b
        case let (.networkError(a), .networkError(b)):
            return a == b
        default:
            return false
        }
    }
}

// MARK: - Hex

/// Lowercase hex encoding/decoding per index.md §5.
///
/// Decoding is case-insensitive and rejects odd-length input and non-hex
/// characters.  Encoding always emits lowercase.
enum Hex {

    private static let table: [Character] = Array("0123456789abcdef")

    /// Encode `data` as lowercase hex.  No separators, no `0x` prefix.
    static func encode(_ data: Data) -> String {
        var out = String()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            let hi = Int(byte >> 4)
            let lo = Int(byte & 0x0F)
            out.append(table[hi])
            out.append(table[lo])
        }
        return out
    }

    /// Decode a hex string into `Data`.  Accepts both upper and lower case.
    /// Throws `SkaldError.invalidKey` on any malformed input — we keep the
    /// generic "invalid" case (not `.invalidQRPayload`) so this helper can be
    /// reused outside the QR code path.
    static func decode(_ hex: String) throws -> Data {
        let chars = Array(hex)
        guard !chars.isEmpty, chars.count % 2 == 0 else {
            throw SkaldError.invalidKey
        }
        var out = Data()
        out.reserveCapacity(chars.count / 2)
        var highNibble: UInt8? = nil
        for c in chars {
            let v: UInt8
            switch c {
            case "0"..."9": v = UInt8(c.asciiValue! - Character("0").asciiValue!)
            case "a"..."f": v = UInt8(c.asciiValue! - Character("a").asciiValue!) + 10
            case "A"..."F": v = UInt8(c.asciiValue! - Character("A").asciiValue!) + 10
            default:        throw SkaldError.invalidKey
            }
            if let h = highNibble {
                out.append((h << 4) | v)
                highNibble = nil
            } else {
                highNibble = v
            }
        }
        return out
    }

    /// Constant-time equality on `Data`.  Time depends only on the length of
    /// the SHORTER input (we still compare lengths in O(1) at the end — the
    /// length difference is not a secret here, only the contents are).
    ///
    /// Implementation per crypto.md §12 (no early-exit on mismatch).
    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        let n = min(a.count, b.count)
        var result: UInt8 = 0
        for i in 0..<n {
            result |= a[i] ^ b[i]
        }
        // Length difference is encoded as non-zero in `result` if and only if
        // the lengths differ.  After the XOR loop `result` is the OR of all
        // byte differences; a length mismatch doesn't add to it, so we still
        // need an explicit length check.
        return result == 0 && a.count == b.count
    }
}

// MARK: - Base64

/// Standard base64 with padding (RFC 4648 §4) — used ONLY for the AEAD
/// ciphertext blob (crypto.md §6.3, index.md §5).  Hex is used for keys,
/// nonces, signatures and identifiers.
enum Base64 {

    /// Encode `data` as standard base64 with padding.
    static func encode(_ data: Data) -> String {
        return data.base64EncodedString()
    }

    /// Decode a standard base64 string.  Throws `SkaldError.invalidKey` on
    /// invalid input.
    static func decode(_ s: String) throws -> Data {
        guard let d = Data(base64Encoded: s) else {
            throw SkaldError.invalidKey
        }
        return d
    }
}
