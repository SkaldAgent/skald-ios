//
//  RelayClient.swift
//  Skald
//
//  WebSocket client for the Skald relay (relay-protocol.md).
//
//  The app uses this for two distinct flows:
//   - role:"pairing"  : one-shot; open, auth, close
//   - role:"client"   : long-lived; open, auth, exchange messages
//
//  The NSE does NOT use this file — push decryption is local-only.  This
//  file is therefore **app-only**.  The remaining Core files (KeyManager,
//  CryptoEngine, KeychainStore, Payloads, PairingQR, CryptoConstants) are
//  shared with the NSE.
//

import Foundation
import os

// MARK: - Role

/// WebSocket role.  The app only ever uses `pairing` and `client`.
enum RelayRole: String, Codable, Equatable {
    case agent   = "agent"
    case pairing = "pairing"
    case client  = "client"
}

// MARK: - Auth frame shapes (relay-protocol.md §4)

/// `auth` frame for the `agent` role.  Not used by the app but defined here
/// for protocol completeness.
struct AuthAgent: Encodable {
    let type = "auth"
    let role = "agent"
    let agent_ed25519_pub: String
    let signature: String
}

/// `auth` frame for the `pairing` role.
struct AuthPairing: Encodable {
    let type = "auth"
    let role = "pairing"
    let namespace_id: String
    let pairing_token: String
    let client_ed25519_pub: String
    let client_x25519_pub: String
    let device_token: String?
    let platform = "ios"
    let signature: String
}

/// `auth` frame for the `client` role.
struct AuthClient: Encodable {
    let type = "auth"
    let role = "client"
    let namespace_id: String
    let client_ed25519_pub: String
    let device_token: String?
    let platform = "ios"
    let signature: String
}

// MARK: - Control frames we receive

struct ChallengeFrame: Decodable {
    let type: String
    let nonce: String   // hex 64 (32B)
}

struct AuthOk: Decodable {
    let type: String
    let role: String
    let namespace_id: String
}

struct AuthErrorFrame: Decodable {
    let type: String
    let code: String
    let message: String?
}

struct ErrorFrame: Decodable {
    let type: String
    let code: String
    let message: String?
}

/// A `pong` reply we send in response to a `ping`.
struct PongFrame: Encodable {
    let type = "pong"
}

/// An incoming E2E message envelope (relay-protocol.md §5.2).
struct IncomingMessage: Codable, Equatable {
    let type: String
    let from: String         // ed25519 pub hex of sender
    let nonce: String        // hex 24
    let ciphertext: String   // base64 of ct‖tag
    let timestamp: String?   // ISO-8601 advisory
}

// MARK: - RelayClient

/// A thin async/await wrapper over `URLSessionWebSocketTask`.
///
/// Implemented as an `actor`:
///   - The receive loop runs concurrently with auth/send; an actor makes
///     the data-race surface explicit.
///   - Callers in the app (InboxViewModel, PairingViewModel) `await`
///     `runClientSession` from a `Task { ... }` and get a clean cancellation
///     story.
actor RelayClient {

    // MARK: - State

    enum State: Equatable {
        case idle
        case connecting
        case authenticating
        case connected
        case failed(String)
        case closed
    }

    private(set) var state: State = .idle

    // MARK: - Configuration

    let relayURL: URL
    let role: RelayRole
    let namespaceIdHex: String?
    let pairingTokenHex: String?
    let clientEd25519Pub: String
    let clientX25519Pub: String
    /// The agent's ed25519 public key (hex).  Used as the `to` field in E2E
    /// `message` envelopes (relay-protocol.md §5.1).  Required for the
    /// `sendE2E` path; ignored otherwise.
    let agentEd25519Pub: String?
    let deviceToken: String?
    let platform: String = "ios"

    // MARK: - Internals

    private var session: URLSession = .shared
    private var task: URLSessionWebSocketTask?
    private var receiveTask: Task<Void, Never>?

    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "RelayClient")

    // MARK: - Init

    init(relayURL: URL,
         role: RelayRole,
         namespaceIdHex: String? = nil,
         pairingTokenHex: String? = nil,
         clientEd25519Pub: String,
         clientX25519Pub: String,
         agentEd25519Pub: String? = nil,
         deviceToken: String? = nil)
    {
        // Force `/v1/ws` on the URL path and strip any query string (the
        // namespace_id is NEVER in the query string per relay-protocol.md).
        var comps = URLComponents(url: relayURL, resolvingAgainstBaseURL: false)
            ?? URLComponents()
        comps.path = "/v1/ws"
        comps.query = nil
        let normalized = comps.url ?? relayURL
        self.relayURL = normalized
        self.role = role
        self.namespaceIdHex = namespaceIdHex
        self.pairingTokenHex = pairingTokenHex
        self.clientEd25519Pub = clientEd25519Pub
        self.clientX25519Pub = clientX25519Pub
        self.agentEd25519Pub = agentEd25519Pub
        self.deviceToken = deviceToken
    }

    // MARK: - Session lifecycle

    /// Open a WebSocket, complete the challenge-response, then run `perform`
    /// (if supplied) inside the authenticated session.  For the `pairing`
    /// role the convention is to pass a `nil` `perform` and close
    /// immediately after `auth_ok` (the agent takes over from here).
    ///
    /// This function does NOT retry on failure — the caller is responsible
    /// for backoff (ios-app.md §9).
    func runClientSession(
        perform: ((RelayClient) async throws -> Void)? = nil
    ) async throws {
        state = .connecting
        log.debug("connecting to \(self.relayURL.absoluteString, privacy: .public)")

        // Create a fresh session and task.
        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = true
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        let session = URLSession(configuration: config)
        self.session = session
        let task = session.webSocketTask(with: relayURL)
        self.task = task
        task.resume()

        do {
            try await authenticate(task: task)
        } catch {
            state = .failed(String(describing: error))
            task.cancel(with: .goingAway, reason: nil)
            receiveTask?.cancel()
            receiveTask = nil
            self.task = nil
            throw error
        }

        state = .connected

        if let perform = perform {
            try await perform(self)
        }

        await close()
    }

    // MARK: - Auth

    private func authenticate(task: URLSessionWebSocketTask) async throws {
        state = .authenticating

        // 1. Read the challenge.
        let challengeText = try await receiveText(task: task)
        let challenge: ChallengeFrame
        do {
            challenge = try JSONDecoder().decode(ChallengeFrame.self,
                                                 from: Data(challengeText.utf8))
        } catch {
            throw SkaldError.relayError("bad challenge frame")
        }
        guard challenge.type == "challenge" else {
            throw SkaldError.relayError("expected challenge, got \(challenge.type)")
        }
        let nonceRaw: Data
        do {
            nonceRaw = try Hex.decode(challenge.nonce)
        } catch {
            throw SkaldError.relayError("bad challenge nonce")
        }
        guard nonceRaw.count == 32 else {
            throw SkaldError.relayError("challenge nonce must be 32B")
        }

        // 2. Sign the challenge.
        let seed = try KeyManager.shared.loadOrCreateSeed()
        let signature = try KeyManager.shared.signAuthChallenge(
            seed: seed,
            challengeNonceRaw: nonceRaw
        )

        // 3. Send the role-specific auth frame.
        switch role {
        case .agent:
            // Not used by the app; included for protocol completeness.  The
            // agent pubkey is derived from the local seed.
            let kp = try KeyManager.shared.deriveKeys(seed: seed)
            let agentEd = kp.signing.publicKey.rawRepresentation
            let frame = AuthAgent(
                agent_ed25519_pub: Hex.encode(agentEd),
                signature: Hex.encode(signature)
            )
            try await sendText(task: task, encodable: frame)
        case .pairing:
            guard let ns = namespaceIdHex, let token = pairingTokenHex else {
                throw SkaldError.relayError("pairing requires namespace_id and pairing_token")
            }
            let frame = AuthPairing(
                namespace_id: ns,
                pairing_token: token,
                client_ed25519_pub: clientEd25519Pub,
                client_x25519_pub: clientX25519Pub,
                device_token: deviceToken,
                signature: Hex.encode(signature)
            )
            try await sendText(task: task, encodable: frame)
        case .client:
            guard let ns = namespaceIdHex else {
                throw SkaldError.relayError("client auth requires namespace_id")
            }
            let frame = AuthClient(
                namespace_id: ns,
                client_ed25519_pub: clientEd25519Pub,
                device_token: deviceToken,
                signature: Hex.encode(signature)
            )
            try await sendText(task: task, encodable: frame)
        }

        // 4. Read auth_ok / auth_error.
        let replyText = try await receiveText(task: task)
        if let ok = try? JSONDecoder().decode(AuthOk.self,
                                              from: Data(replyText.utf8)),
           ok.type == "auth_ok"
        {
            return
        }
        if let err = try? JSONDecoder().decode(AuthErrorFrame.self,
                                               from: Data(replyText.utf8)),
           err.type == "auth_error"
        {
            throw SkaldError.relayError("auth_error \(err.code): \(err.message ?? "")")
        }
        throw SkaldError.relayError("unexpected auth reply")
    }

    // MARK: - Send

    /// Encode and send a Codable frame as a JSON text message.
    func send<T: Encodable>(_ frame: T) async throws {
        guard let task = task else {
            throw SkaldError.relayError("not connected")
        }
        try await sendText(task: task, encodable: frame)
    }

    /// Encrypt `plaintext` with the given `CryptoEngine`, build a
    /// `message` envelope (relay-protocol.md §5.1), and send it.
    ///
    /// The send counter is atomically incremented in the Keychain BEFORE
    /// the message leaves the wire (crypto.md §6.1: persist before send).
    /// On any subsequent send failure the counter has still been bumped —
    /// that is intentional (anti-replay), and the receiver will simply skip
    /// a counter slot (recoverable because the next snapshot re-syncs
    /// state).
    func sendE2E(plaintext: Data, cryptoEngine: CryptoEngine) async throws {
        // Atomically claim the next counter value.
        let nextCounter = try KeychainStore.shared.incrementCounter(
            for: KeychainStore.Key.sendCounter
        )
        let (nonce, sealed) = try cryptoEngine.seal(
            plaintext: plaintext,
            direction: CryptoConstants.nonceDirClientToAgent,
            counterSource: { nextCounter }
        )

        // The recipient's ed25519 pub.  Per the spec this is the value the
        // relay uses for routing inside the namespace.  The app-side caller
        // (PairingViewModel) has access to `agent_ed25519_pub` from the QR
        // and stores it in the Keychain; we pass it through the
        // `RelayClient` config.
        guard let agentEd = agentEd25519Pub else {
            throw SkaldError.relayError("agent_ed25519_pub not configured")
        }

        struct OutgoingMessage: Encodable {
            let type = "message"
            let to: String
            let nonce: String
            let ciphertext: String
        }
        let envelope = OutgoingMessage(
            to: agentEd,
            nonce: Hex.encode(nonce),
            ciphertext: Base64.encode(sealed)
        )
        try await send(envelope)
    }

    // MARK: - Receive loop

    /// Drive the receive loop until `cancel()` is called, the WS errors,
    /// or the surrounding `Task` is cancelled.  Returns only on a terminal
    /// error (delivered to `onError`) or when the loop is cancelled.
    ///
    /// - `onMessage`: invoked for each incoming `message` envelope.  The
    ///   caller is responsible for AES-GCM decryption (CryptoEngine).
    /// - `onError`:   invoked once for a terminal error, then the loop
    ///   returns.
    ///
    /// Callers typically wrap this in their own `Task { ... }` so they can
    /// cancel it on `viewWillDisappear`, on Logout, etc.
    func receiveLoop(
        onMessage: @escaping @Sendable (IncomingMessage) async -> Void,
        onError: @escaping @Sendable (Error) -> Void
    ) async {
        guard let task = task else {
            onError(SkaldError.relayError("not connected"))
            return
        }
        await Self.receiveLoopInner(
            task: task,
            onMessage: onMessage,
            onError: onError
        )
    }

    /// Loop body.  Factored out so the per-actor state isn't held across
    /// long suspends (better cancellation granularity).
    private static func receiveLoopInner(
        task: URLSessionWebSocketTask,
        onMessage: @escaping @Sendable (IncomingMessage) async -> Void,
        onError: @escaping @Sendable (Error) -> Void
    ) async {
        while !Task.isCancelled {
            do {
                let raw = try await task.receive()
                switch raw {
                case .string(let s):
                    // Ping → JSON pong (relay-protocol.md §8).
                    if s.contains("\"type\":\"ping\"") {
                        let pong = PongFrame()
                        if let data = try? JSONEncoder().encode(pong),
                           let text = String(data: data, encoding: .utf8)
                        {
                            try? await task.send(.string(text))
                        }
                        continue
                    }
                    // Try to decode as an incoming E2E message.
                    if let incoming = try? JSONDecoder().decode(
                        IncomingMessage.self, from: Data(s.utf8))
                    {
                        if incoming.type == "message" {
                            await onMessage(incoming)
                            continue
                        }
                    }
                    // Unknown / non-message frames: ignored (forward-compat).
                case .data:
                    // Binary frames are not part of the Skald protocol;
                    // the relay only emits text.  Ignore.
                    break
                @unknown default:
                    break
                }
            } catch {
                onError(SkaldError.networkError(String(describing: error)))
                return
            }
        }
    }

    // MARK: - Close

    func close() async {
        state = .closed
        receiveTask?.cancel()
        receiveTask = nil
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
        session.invalidateAndCancel()
    }

    // MARK: - Frame I/O helpers

    private func receiveText(task: URLSessionWebSocketTask) async throws -> String {
        let raw = try await task.receive()
        switch raw {
        case .string(let s):
            return s
        case .data(let d):
            guard let s = String(data: d, encoding: .utf8) else {
                throw SkaldError.relayError("non-utf8 frame")
            }
            return s
        @unknown default:
            throw SkaldError.relayError("unexpected ws frame")
        }
    }

    private func sendText<T: Encodable>(task: URLSessionWebSocketTask,
                                        encodable: T) async throws
    {
        let encoder = JSONEncoder()
        // Frames are small; the relay doesn't care about field order.
        let data = try encoder.encode(encodable)
        guard let text = String(data: data, encoding: .utf8) else {
            throw SkaldError.relayError("non-utf8 encode")
        }
        try await task.send(.string(text))
    }
}
