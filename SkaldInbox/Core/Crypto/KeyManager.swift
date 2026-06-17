//
//  KeyManager.swift
//  Skald
//
//  Seed management and key derivation for the Skald crypto layer.
//  See docs/../crypto.md §2 (seed) and §3 (HKDF derivation).
//
//  This file is compiled into BOTH targets (app and NSE).  Keep it
//  extension-safe: no UIKit, no UserNotifications.
//

import CryptoKit
import Foundation
import Security
import os

/// A derived keypair, in-memory only.
///
/// Both private keys are re-derived from the seed at every process start —
/// the seed is the only secret that is persisted (crypto.md §2, §10).
struct SkaldKeypair {
    /// Ed25519 — used for signing (relay auth, payload signatures).
    let signing: Curve25519.Signing.PrivateKey
    /// X25519 — used for ECDH.
    let agreement: Curve25519.KeyAgreement.PrivateKey
}

/// Owns the persistent seed and the HKDF keypair derivation.
final class KeyManager {

    /// Singleton — both the app and the NSE use the same backing Keychain
    /// entry, so a process-local singleton is appropriate.
    static let shared = KeyManager()

    private let store: KeychainStore
    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "KeyManager")

    /// Designated initialiser.  The default `shared` uses the App-Group
    /// `KeychainStore.shared`; tests can inject a custom one.
    init(store: KeychainStore = .shared) {
        self.store = store
    }

    // MARK: - Seed

    /// Return the persistent 32-byte seed, lazily creating it on first use.
    ///
    /// The seed is stored in the App-Group Keychain so the NSE can read it.
    /// Generation: `SecRandomCopyBytes(kSecRandomDefault, 32, ...)` — a
    /// CSPRNG, 256 bits of entropy.
    func loadOrCreateSeed() throws -> Data {
        if let existing = try store.getData(for: KeychainStore.Key.seed) {
            if existing.count == 32 {
                return existing
            } else {
                log.error("seed has wrong length (\(existing.count, privacy: .public)) — regenerating")
            }
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw SkaldError.keychainError(status)
        }
        let seed = Data(bytes)
        try store.setData(seed, for: KeychainStore.Key.seed)
        return seed
    }

    // MARK: - Key derivation (crypto.md §3)

    /// Derive the (ed25519, x25519) keypair from a 32-byte seed using
    /// HKDF-SHA256 with the two domain info strings.
    ///
    /// CryptoKit performs RFC 7748 clamping and RFC 8032 hashing internally —
    /// we MUST NOT pre-process the 32-byte HKDF outputs.
    func deriveKeys(seed: Data) throws -> SkaldKeypair {
        guard seed.count == 32 else {
            throw SkaldError.invalidKey
        }
        let ikm = SymmetricKey(data: seed)
        let salt = CryptoConstants.kdfSalt

        let xRaw = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: CryptoConstants.kdfInfoX25519,
            outputByteCount: 32
        )
        let eRaw = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: CryptoConstants.kdfInfoEd25519,
            outputByteCount: 32
        )

        let xData = xRaw.withUnsafeBytes { Data($0) }
        let eData = eRaw.withUnsafeBytes { Data($0) }

        let agreement = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: xData
        )
        let signing = try Curve25519.Signing.PrivateKey(
            rawRepresentation: eData
        )
        return SkaldKeypair(signing: signing, agreement: agreement)
    }

    // MARK: - Namespace ID (crypto.md §7)

    /// Compute `namespace_id_raw = SHA256(NS_DOMAIN ‖ 0x00 ‖ agent_ed25519_pub)`.
    ///
    /// Returns both the 32 raw bytes (used in AAD, §6.2) and the lowercase
    /// 64-char hex string (used in the QR / auth frames).
    func deriveNamespaceId(agentEd25519Pub: Data) -> (raw: Data, hex: String) {
        var hasher = SHA256()
        hasher.update(data: CryptoConstants.namespaceDomain)
        hasher.update(data: Data([0x00]))
        hasher.update(data: agentEd25519Pub)
        let raw = Data(hasher.finalize())
        return (raw, Hex.encode(raw))
    }

    // MARK: - Relay auth (crypto.md §8)

    /// Sign the relay's challenge.  Message:
    ///   `AUTH_DOMAIN ‖ 0x00 ‖ challenge_nonce_raw(32B)`
    ///
    /// Ed25519 hashes the message internally; we MUST NOT pre-hash with
    /// SHA-256 (per crypto.md §8 warning).
    func signAuthChallenge(seed: Data, challengeNonceRaw: Data) throws -> Data {
        let kp = try deriveKeys(seed: seed)
        var msg = Data(CryptoConstants.authDomain)
        msg.append(0x00)
        msg.append(challengeNonceRaw)
        return try kp.signing.signature(for: msg)
    }
}
