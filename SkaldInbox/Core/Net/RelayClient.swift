//
//  RelayClient.swift
//  Skald
//
//  WebSocket client for the Skald relay — v2 transport
//
//  V2 breaks V1 cleanly: every WebSocket frame is now a **binary** frame
//  (opcode 0x2) carrying exactly one serialized `Skald_Relay_V2_RelayFrame`
//  protobuf message.  V1 used JSON text frames with hex/base64 strings for
//  the crypto envelope; V2 uses raw `bytes` everywhere.  See
//  relay-protocol.md v2 §1 for the rationale.
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
import SwiftProtobuf
import os

// MARK: - Role

/// WebSocket role.  The app only ever uses `pairing` and `client`.
enum RelayRole: String, Codable, Equatable {
    case agent   = "agent"
    case pairing = "pairing"
    case client  = "client"
}

// MARK: - Incoming frame shapes (relay-protocol.md v2 §3, §4)

/// An incoming E2E `Message` envelope (relay-protocol.md v2 §3.2).
///
/// All fields are **raw bytes** (NOT base64/hex).  V1 used hex strings
/// for `from`/`nonce` and base64 for `ciphertext`; V2 is binary
/// end-to-end (relay-protocol.md v2 §1).
struct IncomingMessage: Sendable, Equatable {
    /// 32B raw ed25519 public key of the sender.  The relay rewrites
    /// `to`→`from` on delivery (relay-protocol.md v2 §3.2).
    let from: Data
    /// 12B raw AEAD nonce (DIR ‖ counter, big-endian).
    let nonce: Data
    /// Raw `ct ‖ tag` (no nonce).  Decrypt with `CryptoEngine.open`.
    let ciphertext: Data
    /// `true` if the relay routed this on the live (route-or-fail) channel.
    let live: Bool
}

/// Notice that a `Message{live:true}` could not be routed because the
/// destination peer was offline (relay-protocol.md v2 §3).  The relay
/// did NOT queue and did NOT push.
struct PeerOfflineNotice: Sendable, Equatable {
    /// 32B raw ed25519 public key of the recipient that was offline.
    let peer: Data
}

/// Status of a peer in the namespace (relay-protocol.md v2 §4).
enum PresenceStatus: Sendable, Equatable {
    case online
    case offline
    /// A status we don't recognise — carries the raw enum value.
    case other(Int)
}

/// A `PresenceEvent` from the relay (relay-protocol.md v2 §4).
struct PresenceEventInfo: Sendable, Equatable {
    /// 32B raw ed25519 public key of the peer whose status changed.
    let pubkey: Data
    let status: PresenceStatus
}

// MARK: - RelayClient

/// A thin async/await wrapper over `URLSessionWebSocketTask` for the V2
/// protobuf transport (relay-protocol.md v2).
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
    let clientEd25519Pub: String   // hex (raw 32B)
    let clientX25519Pub: String   // hex (raw 32B)
    let deviceToken: String?

    // MARK: - Internals

    /// The per-session `URLSession` we create in `runClientSession`.  `nil`
    /// until we connect and again after `close()`.  We deliberately do NOT
    /// default this to `URLSession.shared`: `close()` calls
    /// `invalidateAndCancel()`, and invalidating the process-wide shared
    /// session would break all other networking.
    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private var receiveTask: Task<Void, Never>?
    private var keepaliveTask: Task<Void, Never>?

    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "RelayClient")

    // MARK: - Init

    init(relayURL: URL,
         role: RelayRole,
         namespaceIdHex: String? = nil,
         pairingTokenHex: String? = nil,
         clientEd25519Pub: String,
         clientX25519Pub: String,
         deviceToken: String? = nil)
    {
        // Force `/v1/ws` on the URL path and strip any query string (the
        // namespace_id is NEVER in the query string per relay-protocol.md).
        // NOTE: the v2 transport (protobuf) reuses the v1 endpoint path —
        // the relay only routes `/v1/ws` (skald-relay-server lib.rs); the
        // "v2" is the wire encoding, not the URL. See v2/relay-protocol.md.
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
        // Bound the per-read wait so a half-open socket (relay accepted the
        // connection but stopped responding) surfaces as a `receive()` error
        // and lets the session loop reconnect — instead of hanging forever and
        // pinning the URLSession (+ its pending task) in memory.  Our 25s
        // keepalive ping (startKeepalive) keeps socket activity well inside
        // this window, so a *healthy* idle stream is never dropped.  The
        // initial handshake is bounded too: no `challenge` within 60s → fail.
        config.timeoutIntervalForRequest = 60
        // Keep the *resource* timeout infinite: this is a long-lived streaming
        // WS and a finite value would tear down a perfectly healthy connection
        // once it elapsed.  We instead close the connection explicitly when the
        // app backgrounds (MainTabView's scenePhase handler).
        config.timeoutIntervalForResource = .infinity
        let session = URLSession(configuration: config)
        self.session = session
        let task = session.webSocketTask(with: relayURL)
        self.task = task
        task.resume()

        do {
            try await authenticate()
        } catch {
            state = .failed(String(describing: error))
            task.cancel(with: .goingAway, reason: nil)
            receiveTask?.cancel()
            receiveTask = nil
            self.task = nil
            // Invalidate the session we just created — without this, a failed
            // (or cancelled) handshake leaks the URLSession and its pending
            // connection task.  This path runs on every reconnect attempt that
            // can't complete auth, so the leak compounds over time.
            session.invalidateAndCancel()
            self.session = nil
            throw error
        }

        state = .connected
        log.debug("auth ok, state=connected, calling perform")

        startKeepalive()

        if let perform = perform {
            try await perform(self)
        }
        log.debug("perform returned, closing")

        await close()
        log.debug("closed")
    }

    // MARK: - Auth (relay-protocol.md v2 §2)

    /// Run the challenge/response handshake.
    ///
    /// 1. Read `RelayFrame.challenge` (32B nonce).
    /// 2. Sign `AUTH_DOMAIN ‖ 0x00 ‖ nonce` with the client ed25519 key.
    /// 3. Send the role-specific `Auth` variant with the signature.
    /// 4. Read `RelayFrame.auth_ok` (success) or `RelayFrame.auth_error`
    ///    (throws `SkaldError.relayError`).
    private func authenticate() async throws {
        state = .authenticating

        // 1. Read the challenge.
        let nonceRaw = try await receiveChallengeNonce()
        guard nonceRaw.count == 32 else {
            throw SkaldError.relayError("challenge nonce must be 32B (got \(nonceRaw.count))")
        }

        // 2. Sign the challenge.
        let seed = try KeyManager.shared.loadOrCreateSeed()
        let signature = try KeyManager.shared.signAuthChallenge(
            seed: seed,
            challengeNonceRaw: nonceRaw
        )

        // 3. Build the role-specific `Auth` and send it.
        let auth = try makeAuth(signature: signature, seed: seed)
        var frame = Skald_Relay_V2_RelayFrame()
        frame.auth = auth
        try await sendFrame(frame)

        // 4. Read `auth_ok` or `auth_error`.
        let reply = try await receiveFrame()
        switch reply.frame {
        case .authOk:
            return
        case .authError(let err):
            throw SkaldError.relayError("auth_error \(err.code): \(err.message)")
        default:
            throw SkaldError.relayError("unexpected auth reply")
        }
    }

    /// Build the role-specific `Auth` protobuf message.  `signature` is on
    /// the common outer field per spec.  `seed` is reused to derive the
    /// agent pubkey in the (unused-by-app) `.agent` path.
    private func makeAuth(signature: Data, seed: Data) throws -> Skald_Relay_V2_Auth {
        var auth = Skald_Relay_V2_Auth()
        auth.signature = signature
        switch role {
        case .agent:
            // Not used by the app; included for protocol completeness.
            let kp = try KeyManager.shared.deriveKeys(seed: seed)
            var agent = Skald_Relay_V2_AuthAgent()
            agent.agentEd25519Pub = kp.signing.publicKey.rawRepresentation
            auth.agent = agent
        case .pairing:
            guard let nsHex = namespaceIdHex, let tokenHex = pairingTokenHex else {
                throw SkaldError.relayError("pairing requires namespace_id and pairing_token")
            }
            let nsRaw     = try Hex.decode(nsHex)
            let tokenRaw  = try Hex.decode(tokenHex)
            let clientEd  = try Hex.decode(clientEd25519Pub)
            let clientX   = try Hex.decode(clientX25519Pub)
            guard nsRaw.count == 32 else {
                throw SkaldError.relayError("namespace_id must be 32B (got \(nsRaw.count))")
            }
            guard tokenRaw.count == 32 else {
                throw SkaldError.relayError("pairing_token must be 32B (got \(tokenRaw.count))")
            }
            guard clientEd.count == 32 else {
                throw SkaldError.relayError("client_ed25519_pub must be 32B (got \(clientEd.count))")
            }
            guard clientX.count == 32 else {
                throw SkaldError.relayError("client_x25519_pub must be 32B (got \(clientX.count))")
            }
            var pairing = Skald_Relay_V2_AuthPairing()
            pairing.namespaceID = nsRaw
            pairing.clientEd25519Pub = clientEd
            pairing.clientX25519Pub = clientX
            pairing.pairingToken = tokenRaw
            pairing.deviceToken = deviceToken ?? ""
            pairing.platform = .ios
            auth.pairing = pairing
        case .client:
            guard let nsHex = namespaceIdHex else {
                throw SkaldError.relayError("client auth requires namespace_id")
            }
            let nsRaw    = try Hex.decode(nsHex)
            let clientEd = try Hex.decode(clientEd25519Pub)
            guard nsRaw.count == 32 else {
                throw SkaldError.relayError("namespace_id must be 32B (got \(nsRaw.count))")
            }
            guard clientEd.count == 32 else {
                throw SkaldError.relayError("client_ed25519_pub must be 32B (got \(clientEd.count))")
            }
            var client = Skald_Relay_V2_AuthClient()
            client.namespaceID = nsRaw
            client.clientEd25519Pub = clientEd
            client.deviceToken = deviceToken ?? ""
            client.platform = .ios
            auth.client = client
        }
        return auth
    }

    // MARK: - Send

    /// Wrap an **already-sealed** payload in a V2
    /// `Message{ciphertext, nonce, peer, live}` envelope
    /// (relay-protocol.md v2 §3.2), then send it as a binary WebSocket frame.
    ///
    /// This is pure transport: the AEAD seal and the anti-replay send-counter
    /// bump live in `SkaldSession` (crypto.md §6.1).  Keeping `RelayClient`
    /// crypto-agnostic is what lets the same transport carry any feature's
    /// payloads over one connection.
    ///
    /// - Parameters:
    ///   - ciphertext: the sealed blob (`ct ‖ tag`, no nonce).
    ///   - nonce: the 12-byte AEAD nonce (DIR ‖ counter).
    ///   - peer: the recipient's raw 32B Ed25519 public key (the `to` field).
    ///   - live: when `true`, the message is routed on the route-or-fail live
    ///     channel (relay-protocol.md v2 §3).  If the destination peer is
    ///     offline, the relay responds with `PeerOffline` and does NOT queue
    ///     or push.  Set `live = true` for pull-of-current-state traffic
    ///     (e.g. `inbox_request`); leave `false` for event-driven
    ///     notifications that must reach an offline client
    ///     (store-and-forward + push).
    func sendEnvelope(ciphertext: Data,
                      nonce: Data,
                      peer: Data,
                      live: Bool) async throws {
        guard peer.count == 32 else {
            throw SkaldError.relayError("peer must be 32B (got \(peer.count))")
        }
        var msg = Skald_Relay_V2_Message()
        msg.ciphertext = ciphertext
        msg.nonce = nonce
        msg.peer = peer
        msg.live = live
        var frame = Skald_Relay_V2_RelayFrame()
        frame.message = msg
        try await sendFrame(frame)
    }

    /// Ask the relay for the set of peers currently online in our namespace
    /// (relay-protocol.md v2 §4).  The relay replies — to us only — with a
    /// single `PresenceList{online}` frame, surfaced via the receive loop's
    /// `onPresenceList` callback.  Cheap and idempotent; safe to call on every
    /// (re)connect to seed the initial roster before the live `PresenceEvent`
    /// deltas take over.
    func requestPresence() async throws {
        var frame = Skald_Relay_V2_RelayFrame()
        frame.presenceRequest = Skald_Relay_V2_PresenceRequest()
        try await sendFrame(frame)
    }

    // MARK: - Keepalive (native WS ping/pong — relay-protocol.md v2 §1)

    /// Start a background task that pings the WS every 25s so that
    /// middleboxes (NAT, load balancers) don't drop the connection on
    /// their idle timeout.  25s is comfortably below the typical 60-120s
    /// NAT idle window.
    ///
    /// The V1 code used a protobuf `{"type":"ping"}` frame; V2 uses
    /// **native WebSocket pings** (handled transparently by URLSession —
    /// we never see them in the receive loop, and URLSession auto-replies
    /// with pongs when the relay pings us).
    private func startKeepalive() {
        keepaliveTask?.cancel()
        log.info("keepalive: starting (interval=25s)")
        keepaliveTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: 25_000_000_000)
                } catch {
                    // Cancelled.
                    return
                }
                if Task.isCancelled { return }
                await self?.sendPing()
            }
        }
    }

    /// Send a native WebSocket ping.  URLSession responds automatically;
    /// the `pongReceiveHandler` is called when the relay's pong arrives
    /// (or with an error if the WS is dead).
    private func sendPing() async {
        guard let task = task else { return }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            task.sendPing { [log] error in
                if let error = error {
                    log.error("keepalive: ping failed: \(error.localizedDescription, privacy: .public)")
                } else {
                    log.info("keepalive: ping ok")
                }
                cont.resume()
            }
        }
    }

    // MARK: - Receive loop

    /// Drive the receive loop until `cancel()` is called, the WS errors,
    /// or the surrounding `Task` is cancelled.  Returns only on a terminal
    /// error (delivered to `onError`) or when the loop is cancelled.
    ///
    /// - `onMessage`:       invoked for each `RelayFrame.message`.
    /// - `onPeerOffline`:   invoked for each `RelayFrame.peer_offline`
    ///                      (a `live` recipient was offline — relay did NOT
    ///                      queue or push).
    /// - `onPresenceEvent`: invoked for each `RelayFrame.presence_event`.
    /// - `onPresenceList`:  invoked for each `RelayFrame.presence_list` (the
    ///                      relay's reply to our `requestPresence()` — a full
    ///                      snapshot of the namespace's online peers).
    /// - `onError`:         invoked once for a terminal error, then the
    ///                      loop returns.
    ///
    /// Native WebSocket pings and the auto-replies are handled by
    /// URLSession and never appear here.
    ///
    /// Callers typically wrap this in their own `Task { ... }` so they
    /// can cancel it on `viewWillDisappear`, on Logout, etc.
    func receiveLoop(
        onMessage: @escaping @Sendable (IncomingMessage) async -> Void,
        onPeerOffline: @escaping @Sendable (PeerOfflineNotice) async -> Void,
        onPresenceEvent: @escaping @Sendable (PresenceEventInfo) async -> Void,
        onPresenceList: @escaping @Sendable ([Data]) async -> Void,
        onError: @escaping @Sendable (Error) -> Void
    ) async {
        log.debug("receiveLoop: reading self.task")
        guard let task = task else {
            log.error("receiveLoop: self.task is nil!")
            onError(SkaldError.relayError("not connected"))
            return
        }
        log.debug("receiveLoop: task is non-nil, calling receiveLoopInner")
        await Self.receiveLoopInner(
            task: task,
            log: log,
            onMessage: onMessage,
            onPeerOffline: onPeerOffline,
            onPresenceEvent: onPresenceEvent,
            onPresenceList: onPresenceList,
            onError: onError
        )
        log.debug("receiveLoop: receiveLoopInner returned")
    }

    /// Loop body.  Factored out so the per-actor state isn't held across
    /// long suspends (better cancellation granularity).
    private static func receiveLoopInner(
        task: URLSessionWebSocketTask,
        log: Logger,
        onMessage: @escaping @Sendable (IncomingMessage) async -> Void,
        onPeerOffline: @escaping @Sendable (PeerOfflineNotice) async -> Void,
        onPresenceEvent: @escaping @Sendable (PresenceEventInfo) async -> Void,
        onPresenceList: @escaping @Sendable ([Data]) async -> Void,
        onError: @escaping @Sendable (Error) -> Void
    ) async {
        while !Task.isCancelled {
            do {
                let raw = try await task.receive()
                switch raw {
                case .data(let bytes):
                    // V2: every binary frame is one serialized
                    // `RelayFrame` protobuf message.
                    let frame: Skald_Relay_V2_RelayFrame
                    do {
                        frame = try Skald_Relay_V2_RelayFrame(serializedBytes: bytes)
                    } catch {
                        log.error("receiveLoopInner: failed to parse RelayFrame (\(bytes.count)B): \(error.localizedDescription, privacy: .public)")
                        continue
                    }
                    await Self.dispatchFrame(
                        frame,
                        onMessage: onMessage,
                        onPeerOffline: onPeerOffline,
                        onPresenceEvent: onPresenceEvent,
                        onPresenceList: onPresenceList
                    )
                case .string(let s):
                    // V1 sent JSON text frames; V2 only uses binary.  If
                    // we see text, the relay is misconfigured (or someone
                    // is talking to a v1 endpoint by mistake).  Log and
                    // ignore — the spec mandates a binary transport and
                    // we will not try to parse JSON.
                    let preview = String(s.prefix(80))
                    log.warning("receiveLoopInner: ignoring unexpected text frame (\(s.count)B): \(preview, privacy: .public)")
                @unknown default:
                    // Future-proof: any new `Message` cases the SDK might
                    // add are ignored.  The relay cannot escalate our
                    // privileges via a new frame type, so silence is
                    // safe.
                    log.warning("receiveLoopInner: ignoring unknown WS message case")
                }
            } catch {
                log.error("receiveLoopInner: task.receive() threw: \(error.localizedDescription, privacy: .public)")
                onError(SkaldError.networkError(String(describing: error)))
                return
            }
        }
        log.debug("receiveLoopInner: task cancelled, exiting loop")
    }

    /// Dispatch a parsed `RelayFrame` to the appropriate callback.
    /// Control frames (challenge, auth_*, authorize*, pairing_*,
    /// client_paired, error, presence_request) are not expected during the
    /// receive loop (auth is handled in `authenticate` before the loop runs);
    /// they are dropped silently.  `presence_list` IS expected here — it is the
    /// relay's reply to an in-session `requestPresence()`.
    private static func dispatchFrame(
        _ frame: Skald_Relay_V2_RelayFrame,
        onMessage: @escaping @Sendable (IncomingMessage) async -> Void,
        onPeerOffline: @escaping @Sendable (PeerOfflineNotice) async -> Void,
        onPresenceEvent: @escaping @Sendable (PresenceEventInfo) async -> Void,
        onPresenceList: @escaping @Sendable ([Data]) async -> Void
    ) async {
        switch frame.frame {
        case .message(let msg):
            // Validate `peer` length (32B ed25519 pub).  The relay
            // MUST do this server-side (relay-protocol.md v2 §2), but a
            // bad relay shouldn't be able to crash us.
            guard msg.peer.count == 32 else { return }
            let incoming = IncomingMessage(
                from: msg.peer,
                nonce: msg.nonce,
                ciphertext: msg.ciphertext,
                live: msg.live
            )
            await onMessage(incoming)
        case .peerOffline(let notice):
            guard notice.peer.count == 32 else { return }
            await onPeerOffline(PeerOfflineNotice(peer: notice.peer))
        case .presenceEvent(let ev):
            guard ev.pubkey.count == 32 else { return }
            let status: PresenceStatus
            switch ev.status {
            case .online:                  status = .online
            case .offline:                 status = .offline
            case .unspecified:             status = .other(0)
            case .UNRECOGNIZED(let i):     status = .other(i)
            }
            await onPresenceEvent(PresenceEventInfo(pubkey: ev.pubkey, status: status))
        case .presenceList(let list):
            // Snapshot reply to our `requestPresence()`.  Keep only well-formed
            // 32B pubkeys; a misbehaving relay can't make us crash on a bad one.
            await onPresenceList(list.online.filter { $0.count == 32 })
        case .challenge,
             .auth, .authOk, .authError,
             .authorize, .authorizeOk,
             .pairingStart, .pairingReady, .pairingStop, .pairingStopOk,
             .clientPaired,
             .error,
             .presenceRequest:
            // Control frames — not expected during the receive loop.
            return
        case nil:
            // Empty oneof — should not happen, but a misbehaving relay
            // cannot escalate our privileges by sending an empty frame.
            return
        }
    }

    // MARK: - Close

    func close() async {
        state = .closed
        keepaliveTask?.cancel()
        keepaliveTask = nil
        receiveTask?.cancel()
        receiveTask = nil
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
        session?.invalidateAndCancel()
        session = nil
    }

    // MARK: - Frame I/O helpers

    /// Receive one WebSocket message and parse it as a `RelayFrame`.
    /// V2 only uses binary frames, so a text frame here is an error.
    private func receiveFrame() async throws -> Skald_Relay_V2_RelayFrame {
        guard let task = task else {
            throw SkaldError.relayError("not connected")
        }
        let raw = try await task.receive()
        switch raw {
        case .data(let bytes):
            do {
                return try Skald_Relay_V2_RelayFrame(serializedBytes: bytes)
            } catch {
                throw SkaldError.relayError("malformed RelayFrame")
            }
        case .string:
            throw SkaldError.relayError("unexpected text frame in v2")
        @unknown default:
            throw SkaldError.relayError("unexpected WS message case")
        }
    }

    /// Read the first frame and return its challenge nonce (32B).  The
    /// frame MUST be a `RelayFrame.challenge`.
    private func receiveChallengeNonce() async throws -> Data {
        let frame = try await receiveFrame()
        switch frame.frame {
        case .challenge(let ch):
            return ch.nonce
        default:
            throw SkaldError.relayError("expected challenge")
        }
    }

    /// Serialize `frame` and send it as a binary WebSocket message.
    private func sendFrame(_ frame: Skald_Relay_V2_RelayFrame) async throws {
        guard let task = task else {
            throw SkaldError.relayError("not connected")
        }
        let bytes: Data
        do {
            bytes = try frame.serializedData()
        } catch {
            throw SkaldError.relayError("failed to serialize RelayFrame: \(error.localizedDescription)")
        }
        try await task.send(.data(bytes))
    }
}
