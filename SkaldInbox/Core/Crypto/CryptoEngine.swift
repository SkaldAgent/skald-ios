//
//  CryptoEngine.swift
//  Skald
//
//  ECDH (§4), AEAD key derivation (§5) and AES-256-GCM seal/open (§6) with
//  the canonical nonce (DIR‖counter) and AAD (ns_raw‖from‖to).
//
//  This file is compiled into BOTH targets (app and NSE).  Keep it
//  extension-safe: no UIKit, no UserNotifications.
//

import Compression
import CryptoKit
import Foundation

/// All-in-one AEAD engine for a single peer (the agent).
///
/// One `CryptoEngine` instance is bound to **one** (agent_x25519_pub, my
/// identity) pair.  The AES key is **static** for the lifetime of the
/// pairing (no PFS in v1).  Counters are managed by the caller via the
/// `counterSource` / `lastSeenCounter` / `updateLastSeen` closures so the
/// engine does not need to know about `KeychainStore` directly.
final class CryptoEngine {

    // MARK: - Peer identity (constructor inputs)

    /// 32-byte raw X25519 public key of the peer (the agent).  Used for ECDH.
    let agentX25519Pub: Data

    /// 32-byte raw Ed25519 public key of the peer (the agent).  Used as the
    /// `to` field in the AAD when WE are sending, and as the `from` field
    /// when we are receiving.
    let agentEd25519Pub: Data

    /// Our own X25519 private key.  Used for ECDH.
    let myX25519Priv: Curve25519.KeyAgreement.PrivateKey

    /// Our own Ed25519 public key (raw 32B).  Used as the `to` field in AAD
    /// when we are receiving, and as the `from` field when we are sending.
    let myEd25519Pub: Data

    /// 32-byte raw namespace_id (§7) — used in the AAD.
    let namespaceIdRaw: Data

    // MARK: - Init

    init(agentX25519Pub: Data,
         agentEd25519Pub: Data,
         myX25519Priv: Curve25519.KeyAgreement.PrivateKey,
         myEd25519Pub: Data,
         namespaceIdRaw: Data)
    {
        precondition(agentX25519Pub.count == 32, "agent_x25519_pub must be 32B")
        precondition(agentEd25519Pub.count == 32, "agent_ed25519_pub must be 32B")
        precondition(myEd25519Pub.count == 32, "my_ed25519_pub must be 32B")
        precondition(namespaceIdRaw.count == 32, "namespace_id_raw must be 32B")
        self.agentX25519Pub = agentX25519Pub
        self.agentEd25519Pub = agentEd25519Pub
        self.myX25519Priv = myX25519Priv
        self.myEd25519Pub = myEd25519Pub
        self.namespaceIdRaw = namespaceIdRaw
    }

    // MARK: - AEAD key derivation (crypto.md §4 + §5)

    /// Derive the AES-256 key for this peer from the ECDH shared secret.
    ///
    /// `aes_key = HKDF(ikm = shared, salt = SESSION_SALT, info = SESSION_INFO, 32)`.
    func deriveAesKey() throws -> SymmetricKey {
        let peerPub: Curve25519.KeyAgreement.PublicKey
        do {
            peerPub = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: agentX25519Pub
            )
        } catch {
            throw SkaldError.invalidKey
        }
        let shared: SharedSecret
        do {
            shared = try myX25519Priv.sharedSecretFromKeyAgreement(with: peerPub)
        } catch {
            throw SkaldError.invalidKey
        }
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: CryptoConstants.sessionSalt,
            sharedInfo: CryptoConstants.sessionInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Nonce construction (crypto.md §6.1)

    /// Build a 12-byte AEAD nonce: 4 bytes of `direction` (DIR) followed by
    /// 8 bytes of `counter` in big-endian.
    static func makeNonce(direction: [UInt8], counter: UInt64) -> Data {
        precondition(direction.count == 4, "direction must be 4B")
        var n = Data(direction)
        var be = counter.bigEndian
        n.append(Data(bytes: &be, count: 8))
        return n
    }

    // MARK: - AAD construction (crypto.md §6.2)

    /// Build the 96-byte AAD: `namespace_id_raw(32) ‖ from(32) ‖ to(32)`.
    /// All inputs are Ed25519 public keys (32B raw).
    static func makeAad(namespaceIdRaw: Data,
                        fromEd25519Pub: Data,
                        toEd25519Pub: Data) -> Data
    {
        precondition(namespaceIdRaw.count == 32, "namespace_id_raw must be 32B")
        precondition(fromEd25519Pub.count == 32, "from must be 32B")
        precondition(toEd25519Pub.count == 32, "to must be 32B")
        var aad = Data()
        aad.reserveCapacity(96)
        aad.append(namespaceIdRaw)
        aad.append(fromEd25519Pub)
        aad.append(toEd25519Pub)
        return aad
    }

    // MARK: - Seal (crypto.md §6)

    /// Encrypt `plaintext` for the given direction.  `counterSource` MUST
    /// return the next counter value to use (the implementation will not
    /// itself increment — `KeychainStore.incrementCounter` does that and
    /// the caller should pass its result).
    ///
    /// Returns the 12-byte nonce and the sealed blob (`ct ‖ tag`, no nonce).
    func seal(plaintext: Data,
              direction: [UInt8],
              counterSource: () -> UInt64) throws -> (nonce: Data, sealed: Data)
    {
        precondition(direction.count == 4, "direction must be 4B")

        let counter = counterSource()
        let nonce = CryptoEngine.makeNonce(direction: direction, counter: counter)

        // When WE are the sender, `from = my_pub` and `to = agent_ed25519_pub`.
        let aad = CryptoEngine.makeAad(
            namespaceIdRaw: namespaceIdRaw,
            fromEd25519Pub: myEd25519Pub,
            toEd25519Pub: agentEd25519Pub
        )

        let aesKey = try deriveAesKey()
        let gcmNonce: AES.GCM.Nonce
        do {
            gcmNonce = try AES.GCM.Nonce(data: nonce)
        } catch {
            throw SkaldError.invalidNonce
        }

        // V2 framing (v2/framing.md §1): prepend `version(1) ‖ comp(1)` to the
        // plaintext BEFORE AES-GCM sealing.  We always send `comp = 0x00`
        // because our outgoing payloads are small JSON envelopes (well under
        // 1 KiB) — spec §2.3 says the zlib header overhead would negate the
        // gain below that threshold.
        var framed = Data()
        framed.reserveCapacity(2 + plaintext.count)
        framed.append(CryptoConstants.framingVersion)
        framed.append(CryptoConstants.compNone)
        framed.append(plaintext)

        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.seal(framed, using: aesKey,
                                   nonce: gcmNonce, authenticating: aad)
        } catch {
            throw SkaldError.decryptionFailed
        }
        // Combined = ciphertext ‖ tag.
        let sealed = box.ciphertext + box.tag
        return (nonce, sealed)
    }

    // MARK: - Seal (already-framed plaintext, for pipe signaling)

    /// Seal plaintext that is ALREADY framed (caller pre-appended version+comp).
    /// Used by the pipe signaling layer which uses its own framing (version=0x02).
    ///
    /// Identical to `seal` but skips the V2 framing prepend.  All other
    /// behaviour (nonce construction, AAD binding, AES-256-GCM) is unchanged.
    func sealFramed(
        plaintext: Data,
        direction: [UInt8],
        counterSource: () -> UInt64
    ) throws -> (nonce: Data, sealed: Data) {
        precondition(direction.count == 4, "direction must be 4B")

        let counter = counterSource()
        let nonce = CryptoEngine.makeNonce(direction: direction, counter: counter)

        let aad = CryptoEngine.makeAad(
            namespaceIdRaw: namespaceIdRaw,
            fromEd25519Pub: myEd25519Pub,
            toEd25519Pub: agentEd25519Pub
        )

        let aesKey = try deriveAesKey()
        let gcmNonce: AES.GCM.Nonce
        do {
            gcmNonce = try AES.GCM.Nonce(data: nonce)
        } catch {
            throw SkaldError.invalidNonce
        }

        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.seal(plaintext, using: aesKey,
                                   nonce: gcmNonce, authenticating: aad)
        } catch {
            throw SkaldError.decryptionFailed
        }
        let sealed = box.ciphertext + box.tag
        return (nonce, sealed)
    }

    // MARK: - Open (crypto.md §6)

    /// Decrypt and authenticate an incoming sealed blob, returning the raw
    /// framed plaintext `version(1) ‖ comp(1) ‖ body` without interpreting
    /// the framing version.
    ///
    /// Used by `SkaldSession.handleIncoming` so it can dispatch on the version
    /// byte before stripping the header (v0x01 → JSON, v0x02 → pipe signal).
    /// The NSE and other callers that only handle v0x01 should call `open()`
    /// instead, which validates the version and decompresses for you.
    func openFramed(nonce: Data,
                    sealed: Data,
                    direction: [UInt8],
                    lastSeenCounter: () -> UInt64,
                    updateLastSeen: (UInt64) -> Void,
                    fromEd25519Pub: Data,
                    toEd25519Pub: Data) throws -> Data
    {
        precondition(direction.count == 4, "direction must be 4B")
        guard nonce.count == 12 else {
            throw SkaldError.invalidNonce
        }
        let dirBytes = Array(nonce.prefix(4))
        if dirBytes != direction {
            throw SkaldError.invalidNonce
        }
        guard toEd25519Pub == myEd25519Pub else {
            throw SkaldError.decryptionFailed
        }
        guard fromEd25519Pub.count == 32 else {
            throw SkaldError.decryptionFailed
        }

        let counterBytes = nonce.subdata(in: 4..<12)
        let counter = counterBytes.withUnsafeBytes { ptr -> UInt64 in
            var be: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &be) { dst in ptr.copyBytes(to: dst) }
            return UInt64(bigEndian: be)
        }
        let last = lastSeenCounter()
        if counter <= last {
            throw SkaldError.counterRegression
        }

        let aad = CryptoEngine.makeAad(
            namespaceIdRaw: namespaceIdRaw,
            fromEd25519Pub: fromEd25519Pub,
            toEd25519Pub: toEd25519Pub
        )
        let aesKey = try deriveAesKey()
        let gcmNonce = try AES.GCM.Nonce(data: nonce)
        let ct = sealed.prefix(sealed.count - 16)
        let tag = sealed.suffix(16)
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)
        } catch {
            throw SkaldError.invalidNonce
        }
        let framed: Data
        do {
            framed = try AES.GCM.open(box, using: aesKey, authenticating: aad)
        } catch {
            throw SkaldError.decryptionFailed
        }
        guard framed.count >= 2 else {
            throw SkaldError.decryptionFailed
        }

        updateLastSeen(counter)
        return framed
    }

    /// Decrypt, authenticate, and strip the V2 framing for a v0x01 JSON payload.
    /// Validates that the framing version is exactly `0x01` and decompresses
    /// the body if needed.  Callers that need to handle multiple framing
    /// versions (pipe signals) should use `openFramed` instead.
    func open(nonce: Data,
              sealed: Data,
              direction: [UInt8],
              lastSeenCounter: () -> UInt64,
              updateLastSeen: (UInt64) -> Void,
              fromEd25519Pub: Data,
              toEd25519Pub: Data) throws -> Data
    {
        let framed = try openFramed(
            nonce: nonce, sealed: sealed, direction: direction,
            lastSeenCounter: lastSeenCounter, updateLastSeen: updateLastSeen,
            fromEd25519Pub: fromEd25519Pub, toEd25519Pub: toEd25519Pub
        )

        // V2 framing strip (v2/framing.md §3).  Reject anything malformed
        // with the same generic `.decryptionFailed` so the caller cannot
        // distinguish a framing error from an AEAD failure (crypto.md §12).
        guard framed[0] == CryptoConstants.framingVersion else {
            throw SkaldError.decryptionFailed
        }
        let comp = framed[1]
        let compressed = framed.subdata(in: 2..<framed.count)

        switch comp {
        case CryptoConstants.compNone:
            return compressed
        case CryptoConstants.compZlib:
            return try Self.zlibDecompress(compressed)
        default:
            throw SkaldError.decryptionFailed
        }
    }

    // MARK: - Framing helpers (v2/framing.md)

    /// Decode a zlib-wrapped (RFC 1950) DEFLATE stream using the iOS
    /// `Compression` framework (`COMPRESSION_ZLIB`).
    ///
    /// `compression_decode_buffer` returns 0 both on error AND on a valid
    /// empty output — but empty JSON payloads do not exist in our protocol,
    /// so `decoded > 0` is a safe success check.
    ///
    /// For small payloads (~few KB) we allocate a generously oversized
    /// output buffer (8× source, minimum 64 KiB) to avoid a two-pass loop
    /// — that's cheap and well below the 512 KiB live-frame ceiling.
    static func zlibDecompress(_ data: Data) throws -> Data {
        let capacity = max(data.count * 8, 64 * 1024)
        let dest = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        defer { dest.deallocate() }
        let decoded = data.withUnsafeBytes { src -> Int in
            guard let srcPtr = src.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return compression_decode_buffer(
                dest, capacity,
                srcPtr, data.count,
                nil, COMPRESSION_ZLIB
            )
        }
        guard decoded > 0 else {
            throw SkaldError.decryptionFailed
        }
        return Data(bytes: dest, count: decoded)
    }
}
