//
//  SkaldInboxTests.swift
//  SkaldTests
//
//  Crypto interop tests against test-vectors.md §4.
//
//  NOTE (V2 transport migration): the V14 `sealed_a2c` vector and the
//  hard-coded `AES.GCM.open(…)` path in `testSealOpenA2C` are written
//  against the V1 *raw* plaintext.  After the v2/framing.md §1 framing
//  change in `CryptoEngine`, the engine seals the FRAMED plaintext, so
//  that direct AES.GCM.open assertion is expected to FAIL.  The fix
//  (regenerate V14 with the framed plaintext, update the vector path to
//  match) lands in the `tests-and-build` task.  This task only adds
//  framing and is intentionally leaving the test as-is.
//

import XCTest
import CryptoKit
@testable import Skald

final class SkaldTests: XCTestCase {

    // V1..V8 from test-vectors.md §4
    private let seedAgent:  Data = Data((0..<32).map { UInt8($0) })
    private let seedClient: Data = Data((32..<64).map { UInt8($0) })

    // V2 agent_x25519_pub
    private let v2_agentX25519Pub_hex = "4fcb9922300372851653f0d8a0d48855674b6f6095e3770273d212bcaf51bc64"
    // V4 agent_ed25519_pub
    private let v4_agentEd25519Pub_hex = "b3e202f4ac99fd9929da47df20adedd5b2598411a466a229f086eda3467ffa7b"
    // V6 client_x25519_pub
    private let v6_clientX25519Pub_hex = "fc472466d9013da9a50a49b6031cde99c1cfd11c87ee04fe4da952417a1f7337"
    // V8 client_ed25519_pub
    private let v8_clientEd25519Pub_hex = "12355ea750e60d6370ba6776037f25062f6c9450c5009669884895fd5b377a18"
    // V9 namespace_id (hex)
    private let v9_namespaceId_hex = "f7d340d3c3f0b0052fa904ba60ebd38a0f7e7d10672ac80648991a2c632c9e58"
    // V11 aes_key (hex)
    private let v11_aesKey_hex = "74fb4ffcbbe069859cfb0790023811554dad328d9f4ac4a1d28077086e33a4e7"
    // V13 aad_a2c (hex, 96B)
    private let v13_aadA2C_hex = "f7d340d3c3f0b0052fa904ba60ebd38a0f7e7d10672ac80648991a2c632c9e58" +
                                  "b3e202f4ac99fd9929da47df20adedd5b2598411a466a229f086eda3467ffa7b" +
                                  "12355ea750e60d6370ba6776037f25062f6c9450c5009669884895fd5b377a18"
    // V14 sealed_a2c base64
    private let v14_sealedA2C_b64 = "bJlpSguoUICTSQi16wvPNdc7SGfmrRTucnIQ6L+awMg1hicXD3KvyRhsdieCSK7zS8tF1a4Pb0uzdcYPNIPz0BX/Ur3nDOKiUiTSOWza4voe+PDpJyVkd60TxavL3sHLfDurW6bt2CUMzeAlNYWsXPfp4AXSo+DK+MH7C6J9U+Fsei66RaG32uipWfXNbj8zOAQCjPuKpkseyI9Gtu5V5ue0H2PNAxNggBq8LWA5DYn5DnQ2oNiaVRgW4STwlWKD2bCqhj4s97im3PlECjF7ngSFX5lJf9pgYqBVheLpJY42o9zJAGnmvK8ZaSMR6t4DVCIKRYRezmthjvaYVMMRfdQODCDFYJTM8QZMmc4KeZw="
    // V18 auth_sig_client hex — the *deterministic* dalek reference value (see
    // "Note on V18" in test-vectors.md §4).  CryptoKit produces a *different*
    // valid signature on every invocation (non-deterministic), so the iOS test
    // below cannot assert byte equality with this value; it asserts that the
    // produced signature (a) has the canonical Ed25519 shape and (b) is valid
    // under the dalek reference.  The dalek value is also accepted by
    // CryptoKit (see testAuthSignatureCrossCompatWithDalek), confirming the
    // interop invariant in both directions.
    private let v18_authSigClient_hex = "ae38491a1f25bb5fb11f0b17e3d344412bfc927461b6517e9a0ab6a64020054677f59490af026f34c81d9378d4daae4823109ca2d1afbf4ff00230a038270002"

    private let challengeNonceHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    private let plaintextA2C = Data(#"""
{"v":1,"kind":"inbox_update","id":"00000000-0000-4000-8000-000000000001","ts":1750000000000,"badge":1,"approvals":[{"request_id":"appr_test_1","tool_name":"send_email","agent_label":"Skald","summary":"Test","created_at":1750000000000}],"clarifications":[]}
"""#.utf8)

    // MARK: - Hex / Base64 helpers

    func testHexRoundtrip() throws {
        let original = Data([0xde, 0xad, 0xbe, 0xef, 0x00, 0xff])
        let hex = Hex.encode(original)
        XCTAssertEqual(hex, "deadbeef00ff")
        let decoded = try Hex.decode(hex)
        XCTAssertEqual(decoded, original)
        // Case-insensitive accept
        XCTAssertEqual(try Hex.decode("DEADBEEF00FF"), original)
    }

    func testBase64StandardPadding() throws {
        let original = Data([0x00, 0x01, 0x02, 0x03, 0xfd, 0xfe, 0xff])
        let b64 = Base64.encode(original)
        XCTAssertTrue(b64.hasSuffix("==") || b64.hasSuffix("="), "expected padding, got \(b64)")
        XCTAssertEqual(try Base64.decode(b64), original)
    }

    // MARK: - V1..V8 (key derivation)

    func testKeyDerivationFromSeeds() throws {
        let kpAgent  = try KeyManager.shared.deriveKeys(seed: seedAgent)
        let kpClient = try KeyManager.shared.deriveKeys(seed: seedClient)
        XCTAssertEqual(Hex.encode(kpAgent.agreement.publicKey.rawRepresentation),  v2_agentX25519Pub_hex)
        XCTAssertEqual(Hex.encode(kpAgent.signing.publicKey.rawRepresentation),    v4_agentEd25519Pub_hex)
        XCTAssertEqual(Hex.encode(kpClient.agreement.publicKey.rawRepresentation), v6_clientX25519Pub_hex)
        XCTAssertEqual(Hex.encode(kpClient.signing.publicKey.rawRepresentation),   v8_clientEd25519Pub_hex)
    }

    // MARK: - V9 (namespace_id)

    func testNamespaceIdDerivation() throws {
        let agentEd = try Hex.decode(v4_agentEd25519Pub_hex)
        let result = KeyManager.shared.deriveNamespaceId(agentEd25519Pub: agentEd)
        XCTAssertEqual(result.hex, v9_namespaceId_hex)
    }

    // MARK: - V10..V11 (ECDH + aes_key)

    func testAesKeyDerivation() throws {
        let kpAgent  = try KeyManager.shared.deriveKeys(seed: seedAgent)
        let kpClient = try KeyManager.shared.deriveKeys(seed: seedClient)
        let agentX  = try Hex.decode(v2_agentX25519Pub_hex)
        let clientX = try Hex.decode(v6_clientX25519Pub_hex)
        let agentEd = try Hex.decode(v4_agentEd25519Pub_hex)
        let nsRaw   = try Hex.decode(v9_namespaceId_hex)

        let engineA = CryptoEngine(agentX25519Pub: agentX, agentEd25519Pub: agentEd,
                                   myX25519Priv: kpClient.agreement,
                                   myEd25519Pub: kpClient.signing.publicKey.rawRepresentation,
                                   namespaceIdRaw: nsRaw)
        let aes = try engineA.deriveAesKey()
        let keyBytes = aes.withUnsafeBytes { Data($0) }
        XCTAssertEqual(Hex.encode(keyBytes), v11_aesKey_hex)
    }

    // MARK: - V14 (sealed_a2c round-trip)

    func testSealOpenA2C() throws {
        let kpAgent  = try KeyManager.shared.deriveKeys(seed: seedAgent)
        let kpClient = try KeyManager.shared.deriveKeys(seed: seedClient)
        let agentX  = try Hex.decode(v2_agentX25519Pub_hex)
        let clientX = try Hex.decode(v6_clientX25519Pub_hex)
        let agentEd = try Hex.decode(v4_agentEd25519Pub_hex)
        let clientEd = try Hex.decode(v8_clientEd25519Pub_hex)
        let nsRaw   = try Hex.decode(v9_namespaceId_hex)

        // Build the engine on the client side: from=agent, to=client.
        let engineClient = CryptoEngine(agentX25519Pub: agentX, agentEd25519Pub: agentEd,
                                        myX25519Priv: kpClient.agreement,
                                        myEd25519Pub: clientEd,
                                        namespaceIdRaw: nsRaw)

        let aes = try engineClient.deriveAesKey()
        let nonceBytes = try Hex.decode("000000010000000000000001")
        let sealedBytes = try Base64.decode(v14_sealedA2C_b64)
        let aadBytes = try Hex.decode(v13_aadA2C_hex)

        // Open with the EXACT AAD and nonce from the vector.
        // sealed_a2c format is ciphertext‖tag (16B), no nonce prepended.
        let ct = sealedBytes.prefix(sealedBytes.count - 16)
        let tag = sealedBytes.suffix(16)
        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceBytes),
                                              ciphertext: ct, tag: tag)
        let cipher = try AES.GCM.open(sealedBox, using: aes, authenticating: aadBytes)
        XCTAssertEqual(cipher, plaintextA2C, "decrypted plaintext must match PLAINTEXT_A2C from §1")

        // Round-trip via CryptoEngine: we need a *matching* engine for the
        // agent side too, because `open` enforces `toEd25519Pub == myEd25519Pub`.
        // The agent-side engine has the client as its peer, so:
        //   - its `agentX25519Pub` (i.e. the *peer's* x25519 pub) is `clientX`
        //   - its `myX25519Priv` is the agent's x25519 priv
        //   - its `myEd25519Pub` is `agentEd`  (the agent is "me" here)
        let engineAgent = CryptoEngine(agentX25519Pub: clientX, agentEd25519Pub: clientEd,
                                       myX25519Priv: kpAgent.agreement,
                                       myEd25519Pub: agentEd,
                                       namespaceIdRaw: nsRaw)
        let aesAgent = try engineAgent.deriveAesKey()
        let aesAgentBytes = aesAgent.withUnsafeBytes { Data($0) }
        XCTAssertEqual(Hex.encode(aesAgentBytes), v11_aesKey_hex,
                       "agent-side aes_key must match V11 (symmetric ECDH)")
        var counter: UInt64 = 0
        let (newNonce, newSealed) = try engineAgent.seal(
            plaintext: plaintextA2C,
            direction: CryptoConstants.nonceDirAgentToClient,
            counterSource: { counter += 1; return counter }
        )
        XCTAssertEqual(newNonce, nonceBytes,
                       "agent seal with counter=1 must reproduce V12 nonce")

        let decrypted = try engineClient.open(
            nonce: newNonce,
            sealed: newSealed,
            direction: CryptoConstants.nonceDirAgentToClient,
            lastSeenCounter: { 0 },
            updateLastSeen: { _ in },
            fromEd25519Pub: agentEd,
            toEd25519Pub: clientEd
        )
        XCTAssertEqual(decrypted, plaintextA2C,
                       "client open of agent-sealed envelope must recover PLAINTEXT_A2C")
    }

    // MARK: - V18 (auth signature)

    func testAuthSignature() throws {
        let kpClient = try KeyManager.shared.deriveKeys(seed: seedClient)
        let challenge = try Hex.decode(challengeNonceHex)
        let msg = buildAuthMessage(challenge: challenge)

        // (1) The produced signature has the canonical Ed25519 shape and is
        //     self-valid under the local public key.  We do NOT compare bytes
        //     with V18, because CryptoKit is non-deterministic (see
        //     "Note on V18" in test-vectors.md §4).
        let sig = try KeyManager.shared.signAuthChallenge(seed: seedClient, challengeNonceRaw: challenge)
        XCTAssertEqual(sig.count, 64, "Ed25519 signature must be 64 bytes")
        XCTAssertTrue(kpClient.signing.publicKey.isValidSignature(sig, for: msg),
                      "CryptoKit signature must self-verify under the local pubkey")

        // (2) The dalek reference signature committed in §4 is accepted by
        //     CryptoKit (interop invariant in the verify direction).
        let dalekRef = try Hex.decode(v18_authSigClient_hex)
        XCTAssertTrue(kpClient.signing.publicKey.isValidSignature(dalekRef, for: msg),
                      "CryptoKit must accept the dalek V18 reference for interop")
    }

    /// Cross-compat with the Rust reference: the dalek reference value MUST
    /// be valid under the CryptoKit public key.  The relay's `verify_strict`
    /// (ed25519-dalek 2.2) MUST accept the *non-deterministic* CryptoKit
    /// signatures — see the Rust counterpart in
    /// `crates/skald-relay-server/src/auth.rs::tests::challenge_verifies_cryptokit_signature`.
    func testAuthSignatureCrossCompatWithDalek() throws {
        let kpClient = try KeyManager.shared.deriveKeys(seed: seedClient)
        let challenge = try Hex.decode(challengeNonceHex)
        let msg = buildAuthMessage(challenge: challenge)
        let dalekHex = v18_authSigClient_hex  // already the dalek value
        let dalekSig = try Hex.decode(dalekHex)
        XCTAssertTrue(kpClient.signing.publicKey.isValidSignature(dalekSig, for: msg),
                      "CryptoKit must accept the dalek signature for interop")
    }

    private func buildAuthMessage(challenge: Data) -> Data {
        var m = Data("skald-relay-auth-v1".utf8)
        m.append(0x00)
        m.append(challenge)
        return m
    }

    // MARK: - Counter regression

    func testCounterRegressionIsRejected() throws {
        let kpClient = try KeyManager.shared.deriveKeys(seed: seedClient)
        let agentX  = try Hex.decode(v2_agentX25519Pub_hex)
        let agentEd = try Hex.decode(v4_agentEd25519Pub_hex)
        let clientEd = try Hex.decode(v8_clientEd25519Pub_hex)
        let nsRaw   = try Hex.decode(v9_namespaceId_hex)

        let engine = CryptoEngine(agentX25519Pub: agentX, agentEd25519Pub: agentEd,
                                  myX25519Priv: kpClient.agreement,
                                  myEd25519Pub: clientEd,
                                  namespaceIdRaw: nsRaw)
        let (_, sealed) = try engine.seal(plaintext: Data("x".utf8),
                                          direction: CryptoConstants.nonceDirAgentToClient,
                                          counterSource: { 5 })

        // lastSeen = 5, counter=5 → must reject.
        XCTAssertThrowsError(try engine.open(
            nonce: CryptoEngine.makeNonce(direction: CryptoConstants.nonceDirAgentToClient, counter: 5),
            sealed: sealed,
            direction: CryptoConstants.nonceDirAgentToClient,
            lastSeenCounter: { 5 },
            updateLastSeen: { _ in },
            fromEd25519Pub: agentEd,
            toEd25519Pub: clientEd
        )) { err in
            guard let s = err as? SkaldError else { return XCTFail("expected SkaldError, got \(err)") }
            XCTAssertEqual(s, SkaldError.counterRegression)
        }
    }

    // MARK: - PairingQR namespace_id verification

    func testPairingQRVerification() throws {
        // Build a valid QR using known vectors, then verify.
        let json = """
        {"v":1,"relay_url":"wss://relay.example.com/v1/ws","namespace_id":"\(v9_namespaceId_hex)","agent_ed25519_pub":"\(v4_agentEd25519Pub_hex)","agent_x25519_pub":"\(v2_agentX25519Pub_hex)","pairing_token":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        """
        let qr = try PairingQRData.from(jsonString: json)
        XCTAssertTrue(try qr.verifyNamespaceId(), "valid QR should verify")
    }

    func testPairingQRRejectsBadNamespace() throws {
        // Wrong namespace_id
        let bad = String(repeating: "0", count: 64)
        let json = """
        {"v":1,"relay_url":"wss://relay.example.com/v1/ws","namespace_id":"\(bad)","agent_ed25519_pub":"\(v4_agentEd25519Pub_hex)","agent_x25519_pub":"\(v2_agentX25519Pub_hex)","pairing_token":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
        """
        let qr = try PairingQRData.from(jsonString: json)
        XCTAssertFalse(try qr.verifyNamespaceId(), "wrong namespace_id must fail verification")
    }
}
