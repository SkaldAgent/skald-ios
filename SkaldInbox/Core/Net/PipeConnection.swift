//
//  PipeConnection.swift
//  Skald
//
//  Data-plane: dial `/v1/pipe`, complete the relay auth handshake,
//  then expose send/recv for AES-256-GCM encrypted byte frames.
//
//  See docs/relay/pipe.md §3, §4.
//

import CryptoKit
import Foundation
import os

/// A single E2E-encrypted byte-stream pipe through the relay.
///
/// Created by `SkaldSession.openPipe()` (initiator) or
/// `SkaldSession.acceptPipe()` (responder).  The caller gets an opaque
/// `send`/`recv` interface; all crypto is internal.
actor PipeConnection {

    /// The role of this peer in the pipe — determines nonce direction prefixes.
    enum Role {
        case initiator
        case responder
    }

    // MARK: - Internal state

    private var wsTask: URLSessionWebSocketTask?
    private var session: URLSession?
    private var receiveTask: Task<Void, Never>?

    /// Frame buffer + waiter for single-consumer `recv()`.
    private var frameQueue: [Data?] = []   // nil means "stream ended"
    private var recvWaiter: CheckedContinuation<Data?, any Error>?
    private var streamError: Error?
    private var streamEnded: Bool = false

    // MARK: - Crypto state

    private let pipeKey: SymmetricKey
    private let connectionId: Data
    private var sendCtr: UInt64 = 1
    private var recvCtr: UInt64 = 1
    private let sendDir: [UInt8]
    private let recvDir: [UInt8]

    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "PipeConnection")

    // MARK: - Init (private — use `connect`)

    private init(
        wsTask: URLSessionWebSocketTask,
        session: URLSession,
        pipeKey: SymmetricKey,
        connectionId: Data,
        role: Role
    ) {
        self.wsTask = wsTask
        self.session = session
        self.pipeKey = pipeKey
        self.connectionId = connectionId
        switch role {
        case .initiator:
            self.sendDir = CryptoConstants.nonceDirPipeInitiator
            self.recvDir = CryptoConstants.nonceDirPipeResponder
        case .responder:
            self.sendDir = CryptoConstants.nonceDirPipeResponder
            self.recvDir = CryptoConstants.nonceDirPipeInitiator
        }
    }

    // MARK: - Factory

    /// Dial `/v1/pipe`, complete the relay auth handshake, return the ready channel.
    /// - Parameters:
    ///   - relayUrl: base relay URL (e.g. "wss://relay.example.com")
    ///   - signingKey: our ed25519 signing key
    ///   - myEdPub: our 32B ed25519 pubkey
    ///   - peerEdPub: the peer's 32B ed25519 pubkey
    ///   - namespaceIdRaw: 32B raw namespace ID
    ///   - connectionId: 32B rendezvous key
    ///   - pipeKey: 32B derived from the ephemeral ECDH
    ///   - role: our role (initiator or responder)
    static func connect(
        relayUrl: URL,
        signingKey: Curve25519.Signing.PrivateKey,
        myEdPub: Data,
        peerEdPub: Data,
        namespaceIdRaw: Data,
        connectionId: Data,
        pipeKey: SymmetricKey,
        role: Role
    ) async throws -> PipeConnection {
        let pipeURL = Self.pipeUrl(from: relayUrl)

        // 1. Open the WebSocket
        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = true
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = .infinity
        let session = URLSession(configuration: config)
        let task = session.webSocketTask(with: pipeURL)
        task.resume()

        // 2. Read PipeChallenge (relay speaks first)
        let challengeRaw = try await task.receive()
        guard case .data(let challengeBytes) = challengeRaw else {
            task.cancel(with: .goingAway, reason: nil)
            session.invalidateAndCancel()
            throw SkaldError.relayError("expected binary PipeChallenge frame")
        }

        let challenge: PipeChallenge
        do {
            challenge = try PipeChallenge.decode(from: challengeBytes)
        } catch {
            task.cancel(with: .goingAway, reason: nil)
            session.invalidateAndCancel()
            throw SkaldError.relayError("malformed PipeChallenge: \(error.localizedDescription)")
        }
        guard challenge.nonce.count == 32 else {
            task.cancel(with: .goingAway, reason: nil)
            session.invalidateAndCancel()
            throw SkaldError.relayError("challenge nonce must be 32B")
        }

        // 3. Build and send PipeAuth
        let dest = Data(SHA256.hash(data: peerEdPub))
        let signature = try PipeCrypto.signPipeAuth(
            signingKey: signingKey,
            challengeNonce: challenge.nonce,
            connectionId: connectionId
        )
        let auth = PipeAuth(
            connectionId: connectionId,
            pubkey: myEdPub,
            dest: dest,
            namespaceId: namespaceIdRaw,
            signature: signature
        )
        let authBytes = auth.encode()
        try await task.send(.data(authBytes))

        // 4. Create the PipeConnection — the relay doesn't send an explicit ok;
        //    if auth passes, data frames start flowing. If it fails, the WS is closed.
        let conn = PipeConnection(
            wsTask: task,
            session: session,
            pipeKey: pipeKey,
            connectionId: connectionId,
            role: role
        )

        // 5. Start the receive loop
        await conn.startReceiveLoop()
        return conn
    }

    // MARK: - Public API

    /// Seal and send one application chunk.
    func send(_ plaintext: Data) async throws {
        guard let task = wsTask else {
            throw SkaldError.relayError("pipe closed")
        }

        let nonceBytes = CryptoEngine.makeNonce(direction: sendDir, counter: sendCtr)
        let gcmNonce: AES.GCM.Nonce
        do {
            gcmNonce = try AES.GCM.Nonce(data: nonceBytes)
        } catch {
            throw SkaldError.invalidNonce
        }

        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.seal(plaintext, using: pipeKey,
                                   nonce: gcmNonce, authenticating: connectionId)
        } catch {
            throw SkaldError.decryptionFailed
        }

        let sealed = box.ciphertext + box.tag
        try await task.send(.data(sealed))
        sendCtr += 1
    }

    /// Receive and open the next application chunk. `nil` on clean close.
    func recv() async throws -> Data? {
        // Return buffered frame if available
        if let frame = frameQueue.first {
            frameQueue.removeFirst()
            if frame == nil, let err = streamError {
                throw err
            }
            return frame
        }
        // If stream already ended, return nil / throw error
        if let err = streamError {
            throw err
        }
        if streamEnded {
            return nil
        }
        // Wait for next frame
        return try await withCheckedThrowingContinuation { cont in
            recvWaiter = cont
        }
    }

    /// Close the underlying WebSocket.
    func close() async {
        receiveTask?.cancel()
        receiveTask = nil
        wsTask?.cancel(with: .normalClosure, reason: nil)
        wsTask = nil
        session?.invalidateAndCancel()
        session = nil
        // Signal stream end to any waiting recv()
        streamEnded = true
        deliverFrame(nil)
    }

    // MARK: - Receive loop

    private func startReceiveLoop() {
        receiveTask = Task { [weak self] in
            await self?.runReceiveLoop()
        }
    }

    private func runReceiveLoop() async {
        guard let task = wsTask else { return }

        while !Task.isCancelled {
            let raw: URLSessionWebSocketTask.Message
            do {
                raw = try await task.receive()
            } catch {
                log.error("pipe receive error: \(error.localizedDescription, privacy: .public)")
                deliverError(SkaldError.networkError("pipe receive failed: \(error.localizedDescription)"))
                return
            }

            switch raw {
            case .data(let sealed):
                do {
                    let plaintext = try decryptFrame(sealed)
                    deliverFrame(plaintext)
                } catch {
                    log.error("pipe decrypt failed: \(error.localizedDescription, privacy: .public)")
                    deliverError(SkaldError.decryptionFailed)
                    return
                }
            case .string:
                // Pipe data plane is binary-only; ignore text frames
                log.warning("pipe: ignoring unexpected text frame")
            @unknown default:
                log.warning("pipe: ignoring unknown WS message case")
            }
        }
    }

    // MARK: - Frame crypto

    private func decryptFrame(_ sealed: Data) throws -> Data {
        let nonceBytes = CryptoEngine.makeNonce(direction: recvDir, counter: recvCtr)

        let gcmNonce = try AES.GCM.Nonce(data: nonceBytes)

        // Split sealed into ciphertext + tag
        guard sealed.count > 16 else {
            throw SkaldError.decryptionFailed
        }
        let ct = sealed.prefix(sealed.count - 16)
        let tag = sealed.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)

        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: pipeKey, authenticating: connectionId)
        } catch {
            throw SkaldError.decryptionFailed
        }

        recvCtr += 1
        return plaintext
    }

    // MARK: - Frame delivery

    private func deliverFrame(_ data: Data?) {
        if data == nil { streamEnded = true }
        if let waiter = recvWaiter {
            recvWaiter = nil
            waiter.resume(returning: data)
        } else {
            frameQueue.append(data)
        }
    }

    private func deliverError(_ error: Error) {
        streamError = error
        streamEnded = true
        // Deliver nil with error pending — next recv() call will throw
        if let waiter = recvWaiter {
            recvWaiter = nil
            waiter.resume(throwing: error)
        } else {
            frameQueue.append(nil)
        }
    }

    // MARK: - URL derivation

    /// Derive the pipe WebSocket URL from the relay URL.
    /// Replaces `/v1/ws` with `/v1/pipe`; otherwise appends `/v1/pipe`.
    private static func pipeUrl(from relayUrl: URL) -> URL {
        var comps = URLComponents(url: relayUrl, resolvingAgainstBaseURL: false)
            ?? URLComponents()
        if comps.path.contains("/v1/ws") {
            comps.path = comps.path.replacingOccurrences(of: "/v1/ws", with: "/v1/pipe")
        } else {
            comps.path = "/v1/pipe"
        }
        comps.query = nil
        return comps.url ?? relayUrl
    }
}
