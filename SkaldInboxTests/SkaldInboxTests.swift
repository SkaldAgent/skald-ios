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
import Security
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

// MARK: - Pipe protocol tests (pipe-ios-plan.md §9)

final class PipeTests: XCTestCase {

    // MARK: - Test data (32B / 64B as needed)

    private func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }

    private func makeConnectionId() -> Data { randomBytes(32) }
    private func makeHandshake() -> Data { randomBytes(32) }
    private func makeEdPub() -> Data { randomBytes(32) }
    private func makeNonce() -> Data { randomBytes(32) }
    private func makeSig() -> Data { randomBytes(64) }

    // MARK: - Pipe invite round-trip (MsgPack)

    func testPipeInviteRoundTrip() {
        let inv = PipeInvite(
            connectionId: makeConnectionId(),
            suite: .x25519Sealed,
            handshake: makeHandshake(),
            streamType: "test-stream",
            compress: [.none, .zlib],
            headers: ["x-custom": "value", "x-priority": "high"]
        )
        let encoded = inv.encode()
        let decoded = try! PipeInvite.decode(from: encoded)
        XCTAssertEqual(decoded, inv)
    }

    func testPipeInviteMinimal() {
        let inv = PipeInvite(
            connectionId: makeConnectionId(),
            suite: .x25519Sealed,
            handshake: makeHandshake(),
            streamType: "log",
            compress: [.none],
            headers: [:]
        )
        let encoded = inv.encode()
        let decoded = try! PipeInvite.decode(from: encoded)
        XCTAssertEqual(decoded, inv)
        XCTAssertEqual(decoded.headers, [:])
    }

    // MARK: - Pipe accept round-trip (MsgPack)

    func testPipeAcceptRoundTrip() {
        let acc = PipeAccept(
            connectionId: makeConnectionId(),
            suite: .x25519Sealed,
            handshake: makeHandshake(),
            compress: .zlib
        )
        let encoded = acc.encode()
        let decoded = try! PipeAccept.decode(from: encoded)
        XCTAssertEqual(decoded, acc)
    }

    // MARK: - Pipe reject round-trip (MsgPack)

    func testPipeRejectRoundTrip() {
        let rej = PipeReject(
            connectionId: makeConnectionId(),
            reason: "unsupported stream_type"
        )
        let encoded = rej.encode()
        let decoded = try! PipeReject.decode(from: encoded)
        XCTAssertEqual(decoded, rej)
    }

    func testPipeRejectEmptyReason() {
        let rej = PipeReject(connectionId: makeConnectionId(), reason: "")
        let encoded = rej.encode()
        let decoded = try! PipeReject.decode(from: encoded)
        XCTAssertEqual(decoded, rej)
    }

    // MARK: - PipeSignal externally-tagged

    func testPipeSignalInviteExternallyTagged() {
        let inv = PipeInvite(
            connectionId: makeConnectionId(),
            suite: .x25519Sealed,
            handshake: makeHandshake(),
            streamType: "cmd",
            compress: [.none],
            headers: [:]
        )
        let signal = PipeSignal.invite(inv)
        let encoded = signal.encode()
        let decoded = try! PipeSignal.decode(from: encoded)
        XCTAssertEqual(decoded, signal)
    }

    func testPipeSignalAcceptExternallyTagged() {
        let acc = PipeAccept(
            connectionId: makeConnectionId(),
            suite: .x25519Sealed,
            handshake: makeHandshake(),
            compress: .none
        )
        let signal = PipeSignal.accept(acc)
        let encoded = signal.encode()
        let decoded = try! PipeSignal.decode(from: encoded)
        XCTAssertEqual(decoded, signal)
    }

    func testPipeSignalRejectExternallyTagged() {
        let rej = PipeReject(connectionId: makeConnectionId(), reason: "busy")
        let signal = PipeSignal.reject(rej)
        let encoded = signal.encode()
        let decoded = try! PipeSignal.decode(from: encoded)
        XCTAssertEqual(decoded, signal)
    }

    // MARK: - Cross-language wire compat with rmp-serde (Rust relay/agent)
    //
    // rmp-serde's `to_vec_named` encodes a Rust `Vec<u8>` (without serde_bytes)
    // as a MsgPack *array of ints*, not `bin`. These vectors are the exact bytes
    // emitted by `skald-relay-common`'s `encode(PipeSignal::Accept/Invite)`, so
    // the decoder must accept array-encoded byte fields. Regression for the
    // "pipe accept timeout" the WebView proxy hit on a real device.

    func testPipeSignalAcceptDecodesRmpArrayEncoding() {
        // PipeAccept { connection_id: [0xAB;32], suite: X25519Sealed,
        //              handshake: [0xCD;32], compress: None }
        let hex =
            "81a641636365707484ad636f6e6e656374696f6e5f6964dc0020" +
            String(repeating: "ccab", count: 32) +
            "a57375697465ad7832353531392d7365616c6564a968616e647368616b65dc0020" +
            String(repeating: "cccd", count: 32) +
            "a8636f6d7072657373a46e6f6e65"
        let decoded = try! PipeSignal.decode(from: try! Hex.decode(hex))
        guard case .accept(let acc) = decoded else {
            return XCTFail("expected .accept, got \(decoded)")
        }
        XCTAssertEqual(acc.connectionId, Data(repeating: 0xAB, count: 32))
        XCTAssertEqual(acc.handshake, Data(repeating: 0xCD, count: 32))
        XCTAssertEqual(acc.suite, .x25519Sealed)
        XCTAssertEqual(acc.compress, .none)
    }

    func testPipeSignalInviteDecodesRmpArrayEncoding() {
        // PipeInvite { connection_id: [0xAB;32], suite: X25519Sealed,
        //   handshake: [0xCD;32], stream_type: "http-local-proxy",
        //   compress: [None], headers: {} }
        let hex =
            "81a6496e7669746586ad636f6e6e656374696f6e5f6964dc0020" +
            String(repeating: "ccab", count: 32) +
            "a57375697465ad7832353531392d7365616c6564a968616e647368616b65dc0020" +
            String(repeating: "cccd", count: 32) +
            "ab73747265616d5f74797065b0687474702d6c6f63616c2d70726f7879" +
            "a8636f6d707265737391a46e6f6e65a76865616465727380"
        let decoded = try! PipeSignal.decode(from: try! Hex.decode(hex))
        guard case .invite(let inv) = decoded else {
            return XCTFail("expected .invite, got \(decoded)")
        }
        XCTAssertEqual(inv.connectionId, Data(repeating: 0xAB, count: 32))
        XCTAssertEqual(inv.handshake, Data(repeating: 0xCD, count: 32))
        XCTAssertEqual(inv.streamType, "http-local-proxy")
        XCTAssertEqual(inv.compress, [.none])
    }

    // MARK: - PipeAuth round-trip (MsgPack)

    func testPipeAuthRoundTrip() {
        let auth = PipeAuth(
            connectionId: makeConnectionId(),
            pubkey: makeEdPub(),
            dest: makeEdPub(),
            namespaceId: makeConnectionId(),
            signature: makeSig()
        )
        let encoded = auth.encode()
        let decoded = try! PipeAuth.decode(from: encoded)
        XCTAssertEqual(decoded, auth)
    }

    // MARK: - PipeChallenge round-trip (MsgPack)

    func testPipeChallengeRoundTrip() {
        let ch = PipeChallenge(nonce: makeNonce())
        let encoded = ch.encode()
        let decoded = try! PipeChallenge.decode(from: encoded)
        XCTAssertEqual(decoded, ch)
    }

    // MARK: - MsgPack error cases

    func testMsgPackRejectsGarbage() {
        let garbage = Data([0xFF, 0x00, 0xAB, 0xCD])
        XCTAssertThrowsError(try PipeChallenge.decode(from: garbage))
    }

    func testMsgPackRejectsEmpty() {
        XCTAssertThrowsError(try PipeChallenge.decode(from: Data()))
    }

    func testMsgPackRejectsWrongLengthConnectionId() {
        let encoder = PipeMsgPackEncoder.self
        let encoded = encoder.encode([
            ("connection_id", .binary(Data(count: 31))),
            ("reason", .string("test"))
        ])
        XCTAssertThrowsError(try PipeReject.decode(from: encoded)) { error in
            guard let e = error as? PipeMsgPackError else {
                return XCTFail("expected PipeMsgPackError, got \(error)")
            }
            guard case .invalidLength = e else {
                return XCTFail("expected invalidLength, got \(e)")
            }
        }
    }

    func testMsgPackRejectsWrongLengthSignature() {
        let encoded = PipeMsgPackEncoder.encode([
            ("connection_id", .binary(randomBytes(32))),
            ("pubkey", .binary(randomBytes(32))),
            ("dest", .binary(randomBytes(32))),
            ("namespace_id", .binary(randomBytes(32))),
            ("signature", .binary(randomBytes(63)))  // 63 instead of 64
        ])
        XCTAssertThrowsError(try PipeAuth.decode(from: encoded)) { error in
            guard let e = error as? PipeMsgPackError else {
                return XCTFail("expected PipeMsgPackError, got \(error)")
            }
            guard case .invalidLength = e else {
                return XCTFail("expected invalidLength, got \(e)")
            }
        }
    }

    func testMsgPackRejectsWrongTypeForField() {
        let encoded = PipeMsgPackEncoder.encode([
            ("connection_id", .string("not-binary")),
            ("reason", .string("test"))
        ])
        XCTAssertThrowsError(try PipeReject.decode(from: encoded)) { error in
            guard let e = error as? PipeMsgPackError else {
                return XCTFail("expected PipeMsgPackError, got \(error)")
            }
            guard case .malformed = e else {
                return XCTFail("expected malformed, got \(e)")
            }
        }
    }

    func testMsgPackRejectsUnknownPipeSuite() {
        let encoded = PipeMsgPackEncoder.encode([
            ("connection_id", .binary(randomBytes(32))),
            ("suite", .string("unknown-v99")),
            ("handshake", .binary(randomBytes(32))),
            ("stream_type", .string("log")),
            ("compress", .array([.string("none")])),
            ("headers", .map([]))
        ])
        XCTAssertThrowsError(try PipeInvite.decode(from: encoded))
    }

    func testMsgPackRejectsUnknownSignalVariant() {
        let encoded = PipeMsgPackEncoder.encode([
            ("UnknownVariant", .map([]))
        ])
        XCTAssertThrowsError(try PipeSignal.decode(from: encoded)) { error in
            guard let e = error as? PipeMsgPackError else {
                return XCTFail("expected PipeMsgPackError, got \(error)")
            }
            guard case .malformed = e else {
                return XCTFail("expected malformed, got \(e)")
            }
        }
    }

    func testMsgPackRejectsSignalWithMultipleKeys() {
        let encoded = PipeMsgPackEncoder.encode([
            ("Invite", .map([
                ("connection_id", .binary(randomBytes(32))),
                ("suite", .string("x25519-sealed")),
                ("handshake", .binary(randomBytes(32))),
                ("stream_type", .string("log")),
                ("compress", .array([.string("none")])),
                ("headers", .map([]))
            ])),
            ("Extra", .string("unexpected"))
        ])
        XCTAssertThrowsError(try PipeSignal.decode(from: encoded))
    }

    func testMsgPackRejectsMapKeyNotString() {
        // A MsgPack array as a map key is invalid
        let buf = Data([0x81, 0x90, 0x00, 0xC0])  // fixmap(1): fixarray(0) → nil
        XCTAssertThrowsError(try PipeMsgPackDecoder.decode(buf))
    }

    // MARK: - MsgPack value round-trips

    func testMsgPackNilRoundTrip() {
        let encoded = PipeMsgPackEncoder.encode([("nil_field", .nilValue)])
        let decoded = try! PipeMsgPackDecoder.decode(encoded)
        XCTAssertEqual(decoded.count, 1)
        if case .nilValue = decoded[0].1 {} else { XCTFail("expected nil") }
    }

    func testMsgPackBoolRoundTrip() {
        for v in [true, false] {
            let encoded = PipeMsgPackEncoder.encode([("b", .bool(v))])
            let decoded = try! PipeMsgPackDecoder.decode(encoded)
            if case .bool(let dv) = decoded[0].1, dv == v {} else { XCTFail("expected bool \(v)") }
        }
    }

    func testMsgPackIntRoundTrip() {
        let cases: [Int64] = [0, 1, -1, 127, -32, 128, -128, 255, 256, 65535, 65536,
                               2147483647, -2147483648, Int64.max, Int64.min]
        for v in cases {
            let encoded = PipeMsgPackEncoder.encode([("i", .int(v))])
            let decoded = try! PipeMsgPackDecoder.decode(encoded)
            if case .int(let dv) = decoded[0].1, dv == v {} else { XCTFail("expected int \(v)") }
        }
    }

    func testMsgPackUIntRoundTrip() {
        let cases: [UInt64] = [0, 1, 127, 128, 255, 256, 65535, 65536, 4294967295,
                               4294967296, UInt64.max]
        for v in cases {
            let encoded = PipeMsgPackEncoder.encode([("u", .uint(v))])
            let decoded = try! PipeMsgPackDecoder.decode(encoded)
            if case .uint(let dv) = decoded[0].1, dv == v {} else { XCTFail("expected uint \(v)") }
        }
    }

    func testMsgPackStringRoundTrip() {
        let cases = ["", "a", "hello world", String(repeating: "x", count: 100)]
        for s in cases {
            let encoded = PipeMsgPackEncoder.encode([("s", .string(s))])
            let decoded = try! PipeMsgPackDecoder.decode(encoded)
            if case .string(let ds) = decoded[0].1, ds == s {} else { XCTFail("expected string '\(s)'") }
        }
    }

    func testMsgPackBinaryRoundTrip() {
        let cases: [Data] = [Data(), Data([0x00]), randomBytes(1), randomBytes(255),
                              randomBytes(256), randomBytes(1000)]
        for d in cases {
            let encoded = PipeMsgPackEncoder.encode([("bin", .binary(d))])
            let decoded = try! PipeMsgPackDecoder.decode(encoded)
            if case .binary(let dd) = decoded[0].1, dd == d {} else { XCTFail("expected binary len \(d.count)") }
        }
    }

    func testMsgPackNestedMapRoundTrip() {
        let inner: [(String, PipeMsgPackValue)] = [
            ("key1", .string("val1")),
            ("key2", .int(42))
        ]
        let outer: [(String, PipeMsgPackValue)] = [
            ("outer", .map(inner)),
            ("flag", .bool(true))
        ]
        let encoded = PipeMsgPackEncoder.encode(outer)
        let decoded = try! PipeMsgPackDecoder.decode(encoded)
        XCTAssertEqual(decoded.count, 2)
        if case .map(let m) = decoded[0].1 {
            XCTAssertEqual(m.count, 2)
        } else { XCTFail("expected nested map") }
    }

    func testMsgPackArrayRoundTrip() {
        let arr: [PipeMsgPackValue] = [.uint(1), .uint(2), .string("three")]
        let encoded = PipeMsgPackEncoder.encode([("arr", .array(arr))])
        let decoded = try! PipeMsgPackDecoder.decode(encoded)
        if case .array(let da) = decoded[0].1 {
            XCTAssertEqual(da.count, 3)
        } else { XCTFail("expected array") }
    }

    // MARK: - Pipe key derivation symmetry

    func testPipeKeyDerivationSymmetry() throws {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()

        let sharedAB = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
        let sharedBA = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)

        let keyAB = PipeCrypto.derivePipeKey(sharedSecret: sharedAB)
        let keyBA = PipeCrypto.derivePipeKey(sharedSecret: sharedBA)

        let dataAB = keyAB.withUnsafeBytes { Data($0) }
        let dataBA = keyBA.withUnsafeBytes { Data($0) }
        XCTAssertEqual(dataAB, dataBA, "both peers must derive the same pipe key")
        XCTAssertEqual(dataAB.count, 32, "pipe key must be 32 bytes")
    }

    func testPipeKeyDerivationDeterministic() throws {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()
        let shared = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)

        let key1 = PipeCrypto.derivePipeKey(sharedSecret: shared)
        let key2 = PipeCrypto.derivePipeKey(sharedSecret: shared)

        let data1 = key1.withUnsafeBytes { Data($0) }
        let data2 = key2.withUnsafeBytes { Data($0) }
        XCTAssertEqual(data1, data2, "derivation must be deterministic")
    }

    // MARK: - Pipe auth sign/verify

    func testPipeAuthSignVerify() throws {
        let key = Curve25519.Signing.PrivateKey()
        let nonce = randomBytes(32)
        let cid = randomBytes(32)

        let sig = try PipeCrypto.signPipeAuth(signingKey: key, challengeNonce: nonce, connectionId: cid)
        XCTAssertEqual(sig.count, 64, "Ed25519 signature must be 64 bytes")

        let valid = PipeCrypto.verifyPipeAuth(
            publicKey: key.publicKey,
            challengeNonce: nonce,
            connectionId: cid,
            signature: sig
        )
        XCTAssertTrue(valid, "signature must self-verify")
    }

    func testPipeAuthVerifyFailsWrongNonce() throws {
        let key = Curve25519.Signing.PrivateKey()
        let nonce = randomBytes(32)
        let wrongNonce = randomBytes(32)
        let cid = randomBytes(32)

        let sig = try PipeCrypto.signPipeAuth(signingKey: key, challengeNonce: nonce, connectionId: cid)
        let valid = PipeCrypto.verifyPipeAuth(
            publicKey: key.publicKey,
            challengeNonce: wrongNonce,
            connectionId: cid,
            signature: sig
        )
        XCTAssertFalse(valid, "verification must fail with wrong nonce")
    }

    func testPipeAuthVerifyFailsWrongConnectionId() throws {
        let key = Curve25519.Signing.PrivateKey()
        let nonce = randomBytes(32)
        let cid = randomBytes(32)
        let wrongCid = randomBytes(32)

        let sig = try PipeCrypto.signPipeAuth(signingKey: key, challengeNonce: nonce, connectionId: cid)
        let valid = PipeCrypto.verifyPipeAuth(
            publicKey: key.publicKey,
            challengeNonce: nonce,
            connectionId: wrongCid,
            signature: sig
        )
        XCTAssertFalse(valid, "verification must fail with wrong connection_id")
    }

    func testPipeAuthVerifyFailsWrongKey() throws {
        let keyA = Curve25519.Signing.PrivateKey()
        let keyB = Curve25519.Signing.PrivateKey()
        let nonce = randomBytes(32)
        let cid = randomBytes(32)

        let sig = try PipeCrypto.signPipeAuth(signingKey: keyA, challengeNonce: nonce, connectionId: cid)
        let valid = PipeCrypto.verifyPipeAuth(
            publicKey: keyB.publicKey,
            challengeNonce: nonce,
            connectionId: cid,
            signature: sig
        )
        XCTAssertFalse(valid, "verification must fail with wrong public key")
    }

    func testPipeAuthVerifyFailsTamperedSig() throws {
        let key = Curve25519.Signing.PrivateKey()
        let nonce = randomBytes(32)
        let cid = randomBytes(32)

        var sig = try PipeCrypto.signPipeAuth(signingKey: key, challengeNonce: nonce, connectionId: cid)
        sig[0] ^= 1  // flip one bit

        let valid = PipeCrypto.verifyPipeAuth(
            publicKey: key.publicKey,
            challengeNonce: nonce,
            connectionId: cid,
            signature: sig
        )
        XCTAssertFalse(valid, "tampered signature must fail verification")
    }

    func testPipeAuthMessageFormat() {
        let nonce = Data((0..<32).map { UInt8($0) })
        let cid = Data((32..<64).map { UInt8($0) })
        let msg = PipeCrypto.pipeAuthMessage(challengeNonce: nonce, connectionId: cid)

        // Expected: PIPE_AUTH_DOMAIN(18B) ‖ 0x00(1B) ‖ nonce(32B) ‖ connection_id(32B)
        let domain = CryptoConstants.pipeAuthDomain
        XCTAssertEqual(msg.prefix(domain.count), domain)
        XCTAssertEqual(msg[domain.count], 0x00)
        XCTAssertEqual(msg.subdata(in: (domain.count + 1)..<(domain.count + 1 + 32)), nonce)
        XCTAssertEqual(msg.suffix(32), cid)
        XCTAssertEqual(msg.count, domain.count + 1 + 32 + 32)
    }

    // MARK: - Pipe signal framing

    func testPipeFramingRoundTrip() {
        let body = Data([0x01, 0x02, 0x03, 0x04])
        let framed = PipeCrypto.framePipeSignal(body)

        XCTAssertTrue(PipeCrypto.isPipeSignal(framed))
        let unframed = PipeCrypto.unframePipeSignal(framed)
        XCTAssertEqual(unframed, body)
    }

    func testPipeFramingLargeBody() {
        let body = randomBytes(10000)
        let framed = PipeCrypto.framePipeSignal(body)
        XCTAssertTrue(PipeCrypto.isPipeSignal(framed))
        XCTAssertEqual(PipeCrypto.unframePipeSignal(framed), body)
    }

    func testPipeFramingEmptyBody() {
        let body = Data()
        let framed = PipeCrypto.framePipeSignal(body)
        XCTAssertTrue(PipeCrypto.isPipeSignal(framed))
        XCTAssertEqual(PipeCrypto.unframePipeSignal(framed), body)
    }

    func testPipeFramingDoesNotMatchAppPayload() {
        // App payloads use framing version 0x01
        var appFramed = Data([0x01, 0x00])
        appFramed.append(Data([0x7B, 0x7D]))  // "{}"
        XCTAssertFalse(PipeCrypto.isPipeSignal(appFramed))
    }

    func testPipeFramingTooShort() {
        XCTAssertNil(PipeCrypto.unframePipeSignal(Data([0x02])))           // 1 byte
        XCTAssertNil(PipeCrypto.unframePipeSignal(Data()))                 // empty
        XCTAssertNotNil(PipeCrypto.unframePipeSignal(Data([0x02, 0x00])))  // minimum valid
    }

    func testPipeFramingWrongCompression() {
        let framed = Data([0x02, 0x01, 0xAA])  // comp=0x01 instead of 0x00
        XCTAssertNil(PipeCrypto.unframePipeSignal(framed))
    }

    func testPipeFramingWrongVersion() {
        let framed = Data([0x03, 0x00, 0xAA])  // version 0x03
        XCTAssertFalse(PipeCrypto.isPipeSignal(framed))
        XCTAssertNil(PipeCrypto.unframePipeSignal(framed))
    }

    // MARK: - sealFramed (CryptoEngine)

    func testSealFramedRoundTrip() throws {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()
        let signingKey = Curve25519.Signing.PrivateKey()
        let agentEd = randomBytes(32)
        let nsRaw = randomBytes(32)

        let engine = CryptoEngine(
            agentX25519Pub: bob.publicKey.rawRepresentation,
            agentEd25519Pub: agentEd,
            myX25519Priv: alice,
            myEd25519Pub: signingKey.publicKey.rawRepresentation,
            namespaceIdRaw: nsRaw
        )

        let plaintext = Data("pipe signal body".utf8)
        let counter: UInt64 = 42

        let (nonce, sealed) = try engine.sealFramed(
            plaintext: plaintext,
            direction: CryptoConstants.nonceDirClientToAgent,
            counterSource: { counter }
        )

        // Verify nonce structure: DIR(4B) + counter(8B BE)
        let dirBytes = Array(nonce.prefix(4))
        XCTAssertEqual(dirBytes, CryptoConstants.nonceDirClientToAgent)
        let counterBytes = nonce.subdata(in: 4..<12)
        let decodedCounter = counterBytes.withUnsafeBytes { ptr -> UInt64 in
            var be: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &be) { dst in ptr.copyBytes(to: dst) }
            return UInt64(bigEndian: be)
        }
        XCTAssertEqual(decodedCounter, counter)

        // Open raw with AES-GCM (bypass CryptoEngine.open which expects V2 framing)
        let aesKey = try engine.deriveAesKey()
        let aad = CryptoEngine.makeAad(
            namespaceIdRaw: nsRaw,
            fromEd25519Pub: signingKey.publicKey.rawRepresentation,
            toEd25519Pub: agentEd
        )
        let gcmNonce = try AES.GCM.Nonce(data: nonce)
        let ct = sealed.prefix(sealed.count - 16)
        let tag = sealed.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)
        let opened = try AES.GCM.open(box, using: aesKey, authenticating: aad)

        // sealFramed should NOT prepend V2 framing — plaintext round-trips as-is
        XCTAssertEqual(opened, plaintext)
    }

    func testSealFramedDoesNotPrependAppFraming() throws {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()
        let signingKey = Curve25519.Signing.PrivateKey()
        let agentEd = randomBytes(32)
        let nsRaw = randomBytes(32)

        let engine = CryptoEngine(
            agentX25519Pub: bob.publicKey.rawRepresentation,
            agentEd25519Pub: agentEd,
            myX25519Priv: alice,
            myEd25519Pub: signingKey.publicKey.rawRepresentation,
            namespaceIdRaw: nsRaw
        )

        // A payload that is already pipe-framed: starts with 0x02
        let pipeFramed = PipeCrypto.framePipeSignal(Data("pipe body".utf8))

        let (nonce, sealed) = try engine.sealFramed(
            plaintext: pipeFramed,
            direction: CryptoConstants.nonceDirClientToAgent,
            counterSource: { 1 }
        )

        // Raw decrypt
        let aesKey = try engine.deriveAesKey()
        let aad = CryptoEngine.makeAad(
            namespaceIdRaw: nsRaw,
            fromEd25519Pub: signingKey.publicKey.rawRepresentation,
            toEd25519Pub: agentEd
        )
        let gcmNonce = try AES.GCM.Nonce(data: nonce)
        let ct = sealed.prefix(sealed.count - 16)
        let tag = sealed.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)
        let opened = try AES.GCM.open(box, using: aesKey, authenticating: aad)

        // The opened plaintext should still be the pipe-framed body (0x02 prefix)
        // NOT the app framing (0x01 prefix)
        XCTAssertEqual(opened, pipeFramed)
        XCTAssertEqual(opened.first, CryptoConstants.framingVersionPipe,
                       "sealFramed must preserve the pipe-signal framing")
    }

    func testSealVsSealFramedDifference() throws {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()
        let signingKey = Curve25519.Signing.PrivateKey()
        let agentEd = randomBytes(32)
        let nsRaw = randomBytes(32)

        let engine = CryptoEngine(
            agentX25519Pub: bob.publicKey.rawRepresentation,
            agentEd25519Pub: agentEd,
            myX25519Priv: alice,
            myEd25519Pub: signingKey.publicKey.rawRepresentation,
            namespaceIdRaw: nsRaw
        )

        let body = Data("test".utf8)
        let counter: UInt64 = 1

        let (_, sealedRegular) = try engine.seal(
            plaintext: body,
            direction: CryptoConstants.nonceDirClientToAgent,
            counterSource: { counter }
        )
        let (_, sealedFramed) = try engine.sealFramed(
            plaintext: body,
            direction: CryptoConstants.nonceDirClientToAgent,
            counterSource: { counter }
        )

        // seal prepends V2 framing before encryption, so the ciphertext differs
        XCTAssertNotEqual(sealedRegular, sealedFramed,
                          "seal (with framing) and sealFramed (without) must produce different ciphertext")
    }

    // MARK: - Pipe frame encrypt/decrypt (nonce construction, AES-256-GCM)

    func testPipeEncryptDecryptRoundTrip() throws {
        let pipeKey = SymmetricKey(size: .bits256)
        let connectionId = randomBytes(32)
        let plaintext = Data("hello pipe!".utf8)

        // Encrypt as initiator (sendDir = DIR_PIPE_INITIATOR)
        let sendCtr: UInt64 = 1
        var nonceBytes = Data(CryptoConstants.nonceDirPipeInitiator)
        var be = sendCtr.bigEndian
        nonceBytes.append(Data(bytes: &be, count: 8))
        let gcmNonce = try AES.GCM.Nonce(data: nonceBytes)
        let box = try AES.GCM.seal(plaintext, using: pipeKey, nonce: gcmNonce, authenticating: connectionId)
        let sealed = box.ciphertext + box.tag

        // Decrypt as responder (recvDir = DIR_PIPE_INITIATOR)
        let recvNonceBytes = nonceBytes  // same nonce
        let recvGcmNonce = try AES.GCM.Nonce(data: recvNonceBytes)
        let ct = sealed.prefix(sealed.count - 16)
        let tag = sealed.suffix(16)
        let recvBox = try AES.GCM.SealedBox(nonce: recvGcmNonce, ciphertext: ct, tag: tag)
        let decrypted = try AES.GCM.open(recvBox, using: pipeKey, authenticating: connectionId)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testPipeEncryptWrongKeyFails() throws {
        let keyA = SymmetricKey(size: .bits256)
        let keyB = SymmetricKey(size: .bits256)
        let connectionId = randomBytes(32)
        let plaintext = Data("secret".utf8)

        var nonceBytes = Data(CryptoConstants.nonceDirPipeInitiator)
        var be = UInt64(1).bigEndian
        nonceBytes.append(Data(bytes: &be, count: 8))
        let gcmNonce = try AES.GCM.Nonce(data: nonceBytes)
        let box = try AES.GCM.seal(plaintext, using: keyA, nonce: gcmNonce, authenticating: connectionId)
        let sealed = box.ciphertext + box.tag

        let ct = sealed.prefix(sealed.count - 16)
        let tag = sealed.suffix(16)
        let recvBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)
        XCTAssertThrowsError(try AES.GCM.open(recvBox, using: keyB, authenticating: connectionId))
    }

    func testPipeEncryptWrongAadFails() throws {
        let pipeKey = SymmetricKey(size: .bits256)
        let cidA = randomBytes(32)
        let cidB = randomBytes(32)
        let plaintext = Data("secret".utf8)

        var nonceBytes = Data(CryptoConstants.nonceDirPipeInitiator)
        var be = UInt64(1).bigEndian
        nonceBytes.append(Data(bytes: &be, count: 8))
        let gcmNonce = try AES.GCM.Nonce(data: nonceBytes)
        let box = try AES.GCM.seal(plaintext, using: pipeKey, nonce: gcmNonce, authenticating: cidA)
        let sealed = box.ciphertext + box.tag

        let ct = sealed.prefix(sealed.count - 16)
        let tag = sealed.suffix(16)
        let recvBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)
        XCTAssertThrowsError(try AES.GCM.open(recvBox, using: pipeKey, authenticating: cidB))
    }

    func testPipeNonceCounterIncrement() throws {
        let sendDir = CryptoConstants.nonceDirPipeInitiator
        var nonces: [Data] = []
        for ctr: UInt64 in [1, 2, 3] {
            var nonce = Data(sendDir)
            var be = ctr.bigEndian
            nonce.append(Data(bytes: &be, count: 8))
            nonces.append(nonce)
        }
        // All nonces must be different
        XCTAssertEqual(Set(nonces).count, 3)
        // First 4 bytes must all match the direction prefix
        for n in nonces {
            XCTAssertEqual(Array(n.prefix(4)), sendDir)
        }
    }

    func testPipeNonceDirectionSeparation() {
        let initiatorDir = CryptoConstants.nonceDirPipeInitiator
        let responderDir = CryptoConstants.nonceDirPipeResponder

        // Same counter, different direction → different nonces
        var nI = Data(initiatorDir)
        var nR = Data(responderDir)
        var be = UInt64(1).bigEndian
        nI.append(Data(bytes: &be, count: 8))
        nR.append(Data(bytes: &be, count: 8))
        XCTAssertNotEqual(nI, nR)
    }

    // MARK: - CryptoConstants pipe values

    func testPipeConstantsDomainSeparator() {
        XCTAssertEqual(CryptoConstants.pipeAuthDomain, Data("skald-pipe-auth-v1".utf8))
        XCTAssertEqual(CryptoConstants.pipeKdfSalt, Data("skald-pipe-v1".utf8))
        XCTAssertEqual(CryptoConstants.pipeKdfInfo, Data("pipe-aes-256-gcm".utf8))
    }

    func testPipeConstantsDirectionTags() {
        XCTAssertEqual(CryptoConstants.nonceDirPipeInitiator, [0x00, 0x00, 0x00, 0x03])
        XCTAssertEqual(CryptoConstants.nonceDirPipeResponder, [0x00, 0x00, 0x00, 0x04])
        XCTAssertEqual(CryptoConstants.framingVersionPipe, 0x02)
    }

    func testPipeDirectionTagsDontCollideWithApp() {
        // Pipe direction tags must not overlap with app direction tags
        let pipeDirs = Set([CryptoConstants.nonceDirPipeInitiator, CryptoConstants.nonceDirPipeResponder])
        let appDirs = Set([CryptoConstants.nonceDirAgentToClient, CryptoConstants.nonceDirClientToAgent])
        XCTAssertTrue(pipeDirs.isDisjoint(with: appDirs), "pipe and app direction tags must not collide")
    }

    // MARK: - Pipe URL derivation (static method on PipeConnection)

    func testPipeUrlDerivationFromRelayUrl() {
        // Since pipeUrl is private, we test indirectly through the logic.
        // The plan says: replace /v1/ws with /v1/pipe, or append /v1/pipe.
        // Testing the URLComponents logic from PipeConnection.swift §3.5

        func derivePipeUrl(from urlString: String) -> String {
            guard let url = URL(string: urlString) else { return urlString }
            var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) ?? URLComponents()
            if comps.path.contains("/v1/ws") {
                comps.path = comps.path.replacingOccurrences(of: "/v1/ws", with: "/v1/pipe")
            } else {
                comps.path = "/v1/pipe"
            }
            comps.query = nil
            return comps.url?.absoluteString ?? urlString
        }

        XCTAssertEqual(derivePipeUrl(from: "wss://relay.example.com/v1/ws"),
                       "wss://relay.example.com/v1/pipe")
        XCTAssertEqual(derivePipeUrl(from: "wss://relay.example.com:8080/v1/ws"),
                       "wss://relay.example.com:8080/v1/pipe")
        XCTAssertEqual(derivePipeUrl(from: "wss://relay.example.com"),
                       "wss://relay.example.com/v1/pipe")
    }

    // MARK: - IncomingPipe surface type

    func testIncomingPipeEquality() {
        let from = randomBytes(32)
        let cid = randomBytes(32)
        let hs = randomBytes(32)

        let a = IncomingPipe(
            from: from, streamType: "log", headers: ["a": "1"],
            connectionId: cid, suite: .x25519Sealed, peerHandshake: hs
        )
        let b = IncomingPipe(
            from: from, streamType: "log", headers: ["a": "1"],
            connectionId: cid, suite: .x25519Sealed, peerHandshake: hs
        )
        XCTAssertEqual(a, b)
    }

    func testIncomingPipeDifferentHeadersNotEqual() {
        let from = randomBytes(32)
        let cid = randomBytes(32)
        let hs = randomBytes(32)

        let a = IncomingPipe(
            from: from, streamType: "log", headers: ["a": "1"],
            connectionId: cid, suite: .x25519Sealed, peerHandshake: hs
        )
        let b = IncomingPipe(
            from: from, streamType: "log", headers: ["a": "2"],
            connectionId: cid, suite: .x25519Sealed, peerHandshake: hs
        )
        XCTAssertNotEqual(a, b)
    }
}
