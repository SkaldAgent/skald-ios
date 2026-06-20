//
//  PipeCrypto.swift
//  Skald
//
//  Pure functions for the pipe protocol crypto layer.
//  No state, no I/O — just key derivation, signing, and framing.
//
//  See docs/relay/pipe.md §2, §3, §4 for normative reference.
//

import CryptoKit
import Foundation

/// Pure functions for the pipe protocol crypto layer.
/// No state, no I/O — just key derivation, signing, and framing.
enum PipeCrypto {

    // MARK: - Pipe key derivation (pipe.md §4)

    /// Derive the per-pipe AES-256-GCM key from the ephemeral ECDH shared secret.
    /// `derive_pipe_key` in Rust: `hkdf32(eph_shared_secret, PIPE_KDF_SALT, PIPE_KDF_INFO)`
    static func derivePipeKey(sharedSecret: SharedSecret) -> SymmetricKey {
        sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: CryptoConstants.pipeKdfSalt,
            sharedInfo: CryptoConstants.pipeKdfInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Data-plane auth (pipe.md §3.1)

    /// Build the message signed for pipe data-plane auth:
    /// `PIPE_AUTH_DOMAIN ‖ 0x00 ‖ challenge_nonce(32B) ‖ connection_id(32B)`
    static func pipeAuthMessage(challengeNonce: Data, connectionId: Data) -> Data {
        var msg = Data(capacity: CryptoConstants.pipeAuthDomain.count + 1 + 32 + 32)
        msg.append(CryptoConstants.pipeAuthDomain)
        msg.append(0x00)
        msg.append(challengeNonce)
        msg.append(connectionId)
        return msg
    }

    /// Sign the pipe auth challenge. Returns 64-byte Ed25519 signature.
    static func signPipeAuth(
        signingKey: Curve25519.Signing.PrivateKey,
        challengeNonce: Data,
        connectionId: Data
    ) throws -> Data {
        let msg = pipeAuthMessage(challengeNonce: challengeNonce, connectionId: connectionId)
        return try signingKey.signature(for: msg)
    }

    /// Verify a pipe auth signature. Returns `true` if valid.
    static func verifyPipeAuth(
        publicKey: Curve25519.Signing.PublicKey,
        challengeNonce: Data,
        connectionId: Data,
        signature: Data
    ) -> Bool {
        let msg = pipeAuthMessage(challengeNonce: challengeNonce, connectionId: connectionId)
        return publicKey.isValidSignature(signature, for: msg)
    }

    // MARK: - Pipe signal framing (pipe.md §2, framing.md)

    /// Wrap a MsgPack pipe-signaling payload for the E2E channel:
    /// `FRAMING_VERSION_PIPE (0x02) ‖ COMP_NONE (0x00) ‖ msgpack`
    static func framePipeSignal(_ msgpack: Data) -> Data {
        var out = Data(capacity: 2 + msgpack.count)
        out.append(CryptoConstants.framingVersionPipe)
        out.append(CryptoConstants.compNone)
        out.append(msgpack)
        return out
    }

    /// `true` if a decrypted E2E plaintext is a pipe signal (first byte == 0x02).
    static func isPipeSignal(_ framed: Data) -> Bool {
        framed.first == CryptoConstants.framingVersionPipe
    }

    /// Strip the pipe signal framing, returning the inner MsgPack body, or nil.
    static func unframePipeSignal(_ framed: Data) -> Data? {
        guard framed.count >= 2 else { return nil }
        guard framed[0] == CryptoConstants.framingVersionPipe else { return nil }
        guard framed[1] == CryptoConstants.compNone else { return nil }
        return framed.subdata(in: 2..<framed.count)
    }
}
