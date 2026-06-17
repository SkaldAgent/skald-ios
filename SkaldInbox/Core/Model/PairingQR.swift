//
//  PairingQR.swift
//  Skald
//
//  Decoding and validation of the JSON the agent prints inside the pairing
//  QR code.  See docs/../ios-app.md §6 (step 1) and crypto.md §7.
//
//  This file is compiled into BOTH targets (app and NSE).  Keep it
//  extension-safe.
//

import CryptoKit
import Foundation

/// JSON payload of the pairing QR code (ios-app.md §6, step 1).
///
/// Field names match the spec exactly.  All binary values are hex (lowercase)
/// on the wire; the QR contains the JSON text verbatim.
struct PairingQRData: Codable, Equatable {
    let v: Int
    let relay_url: String
    let namespace_id: String        // hex 64
    let agent_ed25519_pub: String   // hex 64
    let agent_x25519_pub: String    // hex 64
    let pairing_token: String       // hex 64
}

// MARK: - Decoding helpers

extension PairingQRData {

    /// Decode a QR scan result (the raw text from AVFoundation) into a
    /// validated `PairingQRData`.  Throws `SkaldError.invalidQRPayload` if
    /// `v != 1` or any field has the wrong length.
    static func from(scanResult: String) throws -> PairingQRData {
        return try from(jsonString: scanResult)
    }

    /// Decode and validate the QR JSON text.
    static func from(jsonString: String) throws -> PairingQRData {
        let data = Data(jsonString.utf8)
        let qr: PairingQRData
        do {
            qr = try JSONDecoder().decode(PairingQRData.self, from: data)
        } catch {
            throw SkaldError.invalidQRPayload
        }
        try qr.validate()
        return qr
    }

    /// Check `v == 1` and the exact hex length of every binary field.
    /// 32 bytes → 64 hex chars.
    func validate() throws {
        guard v == 1 else {
            throw SkaldError.invalidQRPayload
        }
        try Self.expectHexLength(namespace_id,      64, "namespace_id")
        try Self.expectHexLength(agent_ed25519_pub, 64, "agent_ed25519_pub")
        try Self.expectHexLength(agent_x25519_pub,  64, "agent_x25519_pub")
        try Self.expectHexLength(pairing_token,     64, "pairing_token")
    }

    private static func expectHexLength(_ s: String, _ n: Int, _ name: String) throws {
        guard s.count == n else {
            throw SkaldError.invalidQRPayload
        }
        // Cheap check that the string is all hex.  We don't decode here
        // (the KeyManager will, and a real hex/garbage error there is
        // clearer for the user).  Just verify character set.
        for c in s {
            switch c {
            case "0"..."9", "a"..."f", "A"..."F":
                continue
            default:
                throw SkaldError.invalidQRPayload
            }
        }
        _ = name  // silence "unused" if the compiler ever complains
    }
}

// MARK: - namespace_id verification (crypto.md §7)

extension PairingQRData {

    /// Recompute `namespace_id` from the QR's `agent_ed25519_pub` and
    /// constant-time-compare it to the value the QR claims.
    ///
    /// This is the "don't trust the relay" check from ios-app.md §6 step 2.
    /// The relay can rewrite a `namespace_id` it forwards, but it cannot
    /// forge the SHA-256 of `NS_DOMAIN ‖ 0x00 ‖ agent_ed25519_pub` without
    /// controlling the agent key.
    @discardableResult
    func verifyNamespaceId() throws -> Bool {
        let agentEdPub: Data
        do {
            agentEdPub = try Hex.decode(agent_ed25519_pub)
        } catch {
            throw SkaldError.invalidQRPayload
        }
        var hasher = SHA256()
        hasher.update(data: CryptoConstants.namespaceDomain)
        hasher.update(data: Data([0x00]))
        hasher.update(data: agentEdPub)
        let derived = Data(hasher.finalize())

        let claimed: Data
        do {
            claimed = try Hex.decode(namespace_id)
        } catch {
            throw SkaldError.invalidQRPayload
        }
        return Hex.constantTimeEqual(derived, claimed)
    }
}
