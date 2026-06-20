//
//  SkaldSession.swift
//  Skald
//
//  The single, app-wide E2E client.  Owns ONE long-lived authenticated relay
//  connection and exposes a clean facade so that callers never touch the
//  transport, the AEAD engine, or the anti-replay counters directly:
//
//      session.start()                       // open + auth + keep alive (backoff)
//      session.stop()                        // tear down
//      try await session.send(payload, live) // encrypt + send
//      for await p in session.inbound()      // decrypted plaintext, multicast
//      for await s in session.states()       // connection-state changes
//      for await e in session.presence()     // agent online/offline
//      try await session.pair(qr)            // one-shot pairing
//      await session.logout()                // best-effort logout + wipe
//
//  Feature view-models subscribe to `inbound()` and filter the `Payload` cases
//  they care about.  Adding a new feature (e.g. health-sync) is a new `Payload`
//  case + a new subscriber — the session itself does NOT change (OCP).
//
//  Implemented as an `actor`: the reconnect loop, the AEAD seal/open and the
//  counter bookkeeping all run on the session's executor, off the main thread.
//  UI state crosses back to `@MainActor` consumers via the `AsyncStream`s.
//
//  App-only: imports UIKit for the `hello` device info.  The NSE does its own
//  local decryption and never uses this type.
//

import Foundation
import UIKit
import os

actor SkaldSession {

    // MARK: - Public types

    /// Connection lifecycle, surfaced to the UI via `states()`.
    enum ConnectionState: Equatable, Sendable {
        case disconnected
        case connecting
        case connected
        /// Terminal: the relay rejected our identity.  The owner should unpair.
        case unauthorized
    }

    /// Agent reachability, surfaced via `presence()`.  We collapse the relay's
    /// `PresenceEvent` and `PeerOffline` signals (both scoped to the agent)
    /// into this two-state value — the only distinction the app cares about.
    enum AgentPresence: Equatable, Sendable {
        case online
        case offline
    }

    // MARK: - Pipe waiter

    /// Bookkeeping for a pending `openPipe` call.
    struct PipeWaiterEntry {
        let continuation: CheckedContinuation<PipeAccept, any Error>
        let timeoutTask: Task<Void, Never>
    }

    // MARK: - Connection state

    private(set) var connectionState: ConnectionState = .disconnected

    // MARK: - Live-session internals

    private(set) var transport: RelayClient?
    private(set) var engine: CryptoEngine?
    private(set) var identity: PairedIdentity?
    /// Last-seen receive counter, mirrored to the Keychain after every open.
    private var recvCounter: UInt64 = 0
    private var loopTask: Task<Void, Never>?

    /// Post-pairing window: we've persisted credentials but the agent may not
    /// have authorised this device yet.  While `true`, an `unauthorized` reply
    /// is treated as "not yet" (retried with backoff) instead of terminal, per
    /// relay-protocol.md §4.2.  Cleared on the first successful `auth_ok`.
    private var awaitingAuthorization = false

    // MARK: - Multicast consumers

    private var inboundConsumers: [UUID: AsyncStream<Payload>.Continuation] = [:]
    private var presenceConsumers: [UUID: AsyncStream<AgentPresence>.Continuation] = [:]
    private var stateConsumers: [UUID: AsyncStream<ConnectionState>.Continuation] = [:]
    private var errorConsumers: [UUID: AsyncStream<String>.Continuation] = [:]

    // MARK: - Pipe layer state

    /// Pending `openPipe` waiters: connectionId → entry (continuation + timeout task).
    var pipeWaiters: [Data: PipeWaiterEntry] = [:]

    /// Multicast for inbound pipe invites (responder side).
    var incomingPipeConsumers: [UUID: AsyncStream<IncomingPipe>.Continuation] = [:]

    /// Pipe accept timeout (pipe.md).
    static let pipeAcceptTimeout: UInt64 = 30_000_000_000  // 30s in ns

    let log = Logger(subsystem: "net.skaldagent.inbox", category: "SkaldSession")

    /// Keychain flag: have we sent the one-time `hello` for this pairing?
    private static let helloSentKey = "skald.hello_sent"

    init() {}

    // MARK: - Lifecycle

    /// Begin the reconnect loop (the `.client` role).  Idempotent — a no-op if
    /// a loop is already running.
    func start() {
        guard loopTask == nil else { return }
        loopTask = Task { [weak self] in
            await self?.runLoop()
        }
    }

    /// Begin the reconnect loop in "post-pairing" mode: the agent may not have
    /// authorised this device yet, so the loop retries through `unauthorized`
    /// (relay-protocol.md §4.2) until it receives `auth_ok`, instead of treating
    /// the first rejection as terminal.  Called by `PairingViewModel` while the
    /// app is in `.awaitingAuth`.  The flag clears itself on the first connect.
    func startAwaitingAuthorization() {
        awaitingAuthorization = true
        start()
    }

    /// Tear the session down and stop reconnecting.  Safe to call when stopped.
    func stop() async {
        awaitingAuthorization = false
        loopTask?.cancel()
        loopTask = nil
        await closeTransport()
        setState(.disconnected)
    }

    /// Force a fresh session: cancel the current loop and restart.  Used when
    /// the APNs device token arrives or rotates after we already authenticated,
    /// so the handshake re-sends the new token.
    func reconnect() async {
        loopTask?.cancel()
        loopTask = nil
        await closeTransport()
        setState(.disconnected)
        start()
    }

    private func closeTransport() async {
        let t = transport
        transport = nil
        await t?.close()
        cancelAllPipeWaiters()
    }

    // MARK: - Session loop (was InboxViewModel.runSessionLoop)

    private func runLoop() async {
        var attempt = 0
        while !Task.isCancelled {
            let startedAt = Date()
            setState(.connecting)
            do {
                try await runOneSession()
                // `runOneSession` only returns when the receive loop ended —
                // either we were cancelled or the WS dropped underneath us.
                if Task.isCancelled { setState(.disconnected); return }
                // WS dropped while still wanted → fall through to backoff.
            } catch is CancellationError {
                setState(.disconnected)
                return
            } catch let err as SkaldError {
                if case .relayError(let msg) = err, msg.contains("unauthorized") {
                    // Terminal — the relay revoked our identity — UNLESS we're
                    // still in the post-pairing window: the agent may not have
                    // authorised this device yet (relay-protocol.md §4.2), so
                    // `unauthorized` is expected.  Fall through to backoff and
                    // keep retrying until we get `auth_ok`.
                    if !awaitingAuthorization {
                        setState(.unauthorized)
                        return
                    }
                } else {
                    emitError(err.errorDescription ?? "Relay error")
                }
            } catch {
                emitError(error.localizedDescription)
            }
            setState(.disconnected)
            if Task.isCancelled { return }

            // A session that stayed up a while was "healthy": reset the backoff
            // so the next drop reconnects quickly.  A session that died almost
            // immediately keeps climbing, avoiding a hot reconnect loop.
            if Date().timeIntervalSince(startedAt) > 30 { attempt = 0 }

            let base = min(60, 1 << min(attempt, 5))
            let jitter = Double.random(in: 0.8...1.2)
            let delay = Double(base) * jitter
            attempt += 1
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    }

    /// One WS session: load identity, build transport + engine, connect, then
    /// drive the receive loop until it ends.
    private func runOneSession() async throws {
        defer { cancelAllPipeWaiters() }
        let identity = try PairedIdentity.load()
        self.identity = identity
        let transport = identity.makeClientTransport()
        self.transport = transport
        self.engine = identity.makeEngine()
        self.recvCounter = Self.loadRecvCounter()

        try await transport.runClientSession { [weak self] c in
            guard let self else { return }
            await self.handleConnected(c)
        }
    }

    /// Called once the WS is authenticated.  Sends the one-time `hello`, then
    /// drives the receive loop.  The first `inbox_request` is the InboxViewModel's
    /// job (it reacts to `.connected` on the `states()` stream) — the session
    /// stays payload-agnostic.
    private func handleConnected(_ c: RelayClient) async {
        // First successful auth ends the post-pairing window: from now on an
        // `unauthorized` means a real revocation and is terminal.
        awaitingAuthorization = false
        setState(.connected)
        await sendHelloIfNeeded()
        await c.receiveLoop(
            onMessage: { [weak self] msg in
                await self?.handleIncoming(msg)
            },
            onPeerOffline: { [weak self] notice in
                await self?.handlePeerOffline(notice)
            },
            onPresenceEvent: { [weak self] event in
                await self?.handlePresence(event)
            },
            onError: { [weak self] err in
                let descr = (err as? SkaldError)?.errorDescription ?? err.localizedDescription
                Task { await self?.emitError(descr) }
            }
        )
    }

    // MARK: - Receive (decrypt + broadcast)

    private func handleIncoming(_ msg: IncomingMessage) async {
        guard let engine = engine, let identity = identity else { return }
        do {
            // Decrypt to raw framed bytes (version ‖ comp ‖ body) so we can
            // dispatch on the version byte before stripping the header.
            let framed = try engine.openFramed(
                nonce: msg.nonce,
                sealed: msg.ciphertext,
                direction: CryptoConstants.nonceDirAgentToClient,
                lastSeenCounter: { self.recvCounter },
                updateLastSeen: { newValue in
                    self.recvCounter = newValue
                    if let advanced = try? KeychainStore.shared.compareAndAdvanceCounter(
                        for: KeychainStore.Key.recvCounter, to: newValue
                    ) {
                        self.recvCounter = advanced
                    }
                },
                fromEd25519Pub: msg.from,
                toEd25519Pub: identity.myEd25519Pub
            )

            switch framed[0] {
            case CryptoConstants.framingVersionPipe:
                guard let body = PipeCrypto.unframePipeSignal(framed) else {
                    log.warning("malformed pipe signal framing dropped")
                    return
                }
                await handlePipeSignal(from: msg.from, body: body)

            case CryptoConstants.framingVersion:
                let comp = framed[1]
                let bodyData = framed.subdata(in: 2..<framed.count)
                let plaintext: Data
                switch comp {
                case CryptoConstants.compNone:
                    plaintext = bodyData
                case CryptoConstants.compZlib:
                    plaintext = try CryptoEngine.zlibDecompress(bodyData)
                default:
                    log.warning("unknown comp byte \(comp) — dropping")
                    return
                }
                let payload = try JSONDecoder().decode(Payload.self, from: plaintext)
                broadcast(payload)

            default:
                log.warning("unknown framing version \(framed[0]) — dropping")
            }
        } catch let err as SkaldError {
            emitError(String(localized: "Decryption: ") + (err.errorDescription ?? String(localized: "unknown error")))
        } catch {
            emitError(String(localized: "Decryption: ") + error.localizedDescription)
        }
    }

    /// The agent was offline when we sent a `live` message — surface it as
    /// `presence(.offline)`.  Scoped to the agent (the only peer we route to).
    private func handlePeerOffline(_ notice: PeerOfflineNotice) async {
        guard let agentEd = identity?.agentEd25519Pub, notice.peer == agentEd else { return }
        emitPresence(.offline)
    }

    /// A presence change from the relay.  We forward only events about the
    /// agent; subscribers (InboxViewModel) decide what to do (e.g. re-sync).
    private func handlePresence(_ event: PresenceEventInfo) async {
        guard let agentEd = identity?.agentEd25519Pub, event.pubkey == agentEd else { return }
        switch event.status {
        case .online:  emitPresence(.online)
        case .offline: emitPresence(.offline)
        case .other:   break
        }
    }

    // MARK: - Send

    /// Encrypt `payload` and send it to the agent.  The send counter is bumped
    /// atomically in the Keychain BEFORE the frame leaves the wire (crypto.md
    /// §6.1).
    ///
    /// - Parameter live: route on the live (route-or-fail) channel — see
    ///   `RelayClient.sendEnvelope`.
    func send<P: Encodable & Sendable>(_ payload: P, live: Bool = false) async throws {
        guard let transport = transport, let engine = engine, let identity = identity else {
            throw SkaldError.relayError("not connected")
        }
        try await Self.encryptAndSend(
            payload, live: live, engine: engine,
            peer: identity.agentEd25519Pub, via: transport
        )
    }

    /// Shared seal + counter + send, used by the live `send` and the one-shot
    /// transient sends (`sendOneShot`, `logout`).
    private static func encryptAndSend<P: Encodable & Sendable>(
        _ payload: P,
        live: Bool,
        engine: CryptoEngine,
        peer: Data,
        via transport: RelayClient
    ) async throws {
        let plaintext = try JSONEncoder().encode(payload)
        let nextCounter = try KeychainStore.shared.incrementCounter(
            for: KeychainStore.Key.sendCounter
        )
        let (nonce, sealed) = try engine.seal(
            plaintext: plaintext,
            direction: CryptoConstants.nonceDirClientToAgent,
            counterSource: { nextCounter }
        )
        try await transport.sendEnvelope(
            ciphertext: sealed, nonce: nonce, peer: peer, live: live
        )
    }

    /// First-connect handshake: tell the agent about this device.  Sent once
    /// per pairing (gated on a Keychain flag), best-effort.
    private func sendHelloIfNeeded() async {
        guard (try? KeychainStore.shared.getString(for: Self.helloSentKey)) == nil else { return }
        guard let engine = engine, let identity = identity, let transport = transport else { return }
        let hello = Hello(
            v: 1,
            kind: "hello",
            id: UUID().uuidString.lowercased(),
            ts: Self.nowMillis(),
            device_info: await Self.deviceInfo()
        )
        do {
            try await Self.encryptAndSend(
                hello, live: false, engine: engine,
                peer: identity.agentEd25519Pub, via: transport
            )
            try? KeychainStore.shared.setString("1", for: Self.helloSentKey)
        } catch {
            // Best-effort: the agent re-learns the device on the next hello.
        }
    }

    // MARK: - Pairing

    /// One-shot pairing: open a `.pairing` WS, complete the challenge/response,
    /// then persist seed + namespace + agent pubkeys to the Keychain.  The
    /// caller (PairingViewModel) drives the AppState transition afterwards.
    func pair(_ qr: PairingQRData) async throws {
        let seed = try KeyManager.shared.loadOrCreateSeed()
        let keypair = try KeyManager.shared.deriveKeys(seed: seed)

        let agentEd = try Hex.decode(qr.agent_ed25519_pub)
        let ns = KeyManager.shared.deriveNamespaceId(agentEd25519Pub: agentEd)

        guard let url = URL(string: qr.relay_url) else {
            throw SkaldError.relayError("invalid relay URL")
        }
        let deviceToken = (try? KeychainStore.shared.getString(for: KeychainStore.Key.deviceToken)) ?? nil

        let transport = RelayClient(
            relayURL: url,
            role: .pairing,
            namespaceIdHex: ns.hex,
            pairingTokenHex: qr.pairing_token,
            clientEd25519Pub: Hex.encode(keypair.signing.publicKey.rawRepresentation),
            clientX25519Pub: Hex.encode(keypair.agreement.publicKey.rawRepresentation),
            deviceToken: deviceToken
        )

        // Open, auth, close (the agent takes over from `auth_ok`).
        try await transport.runClientSession(perform: nil)

        try Self.persistPairing(seed: seed, namespaceIdRaw: ns.raw, qr: qr, keypair: keypair)
    }

    private static func persistPairing(seed: Data,
                                       namespaceIdRaw: Data,
                                       qr: PairingQRData,
                                       keypair: SkaldKeypair) throws {
        let store = KeychainStore.shared
        try store.setData(seed, for: KeychainStore.Key.seed)
        try store.setData(namespaceIdRaw, for: KeychainStore.Key.namespaceId)
        try store.setString(qr.relay_url, for: KeychainStore.Key.relayUrl)
        try store.setData(Hex.decode(qr.agent_ed25519_pub), for: KeychainStore.Key.agentEd25519Pub)
        try store.setData(Hex.decode(qr.agent_x25519_pub),  for: KeychainStore.Key.agentX25519Pub)
        try store.setData(keypair.signing.publicKey.rawRepresentation,   for: KeychainStore.Key.myEd25519Pub)
        try store.setData(keypair.agreement.publicKey.rawRepresentation, for: KeychainStore.Key.myX25519Pub)
        // Reset both counters to 1 (the NEXT counter to use).
        try store.setData(beU64(1), for: KeychainStore.Key.sendCounter)
        try store.setData(beU64(1), for: KeychainStore.Key.recvCounter)
        // "hello" not sent yet for this pairing.
        try store.delete(for: helloSentKey)
    }

    // MARK: - Logout

    /// Best-effort E2E `logout` to the agent (≤5s), then tear down and wipe
    /// every Keychain entry we own.  The caller drives the AppState transition.
    func logout() async {
        // Tear down the live session first so we don't race a reconnect.
        await stop()

        let payload = LogoutPayload(
            v: 1, kind: "logout",
            id: UUID().uuidString.lowercased(),
            ts: Self.nowMillis()
        )
        // Cap the best-effort send at 5s — the user expects logout to be quick.
        await withTaskGroup(of: Void.self) { group in
            group.addTask { try? await SkaldSession.sendOneShot(payload) }
            group.addTask { try? await Task.sleep(nanoseconds: 5_000_000_000) }
            await group.next()
            group.cancelAll()
        }

        try? KeychainStore.shared.deleteAll()
    }

    // MARK: - One-shot send

    /// Open a transient `.client` WS, send ONE payload, and close.  Used when no
    /// live session is available — notification actions (AppDelegate) and the
    /// logout payload.  Throws if we are not paired.
    static func sendOneShot<P: Encodable & Sendable>(_ payload: P) async throws {
        let identity = try PairedIdentity.load()
        let transport = identity.makeClientTransport()
        try await transport.runClientSession { c in
            let engine = identity.makeEngine()
            try await encryptAndSend(
                payload, live: false, engine: engine,
                peer: identity.agentEd25519Pub, via: c
            )
        }
    }

    // MARK: - Multicast streams

    /// Subscribe to decrypted inbound payloads.  Each call returns an
    /// independent stream; the session fans every payload out to all of them.
    func inbound() -> AsyncStream<Payload> {
        var cont: AsyncStream<Payload>.Continuation!
        let stream = AsyncStream<Payload> { cont = $0 }
        let id = UUID()
        inboundConsumers[id] = cont
        cont.onTermination = { [weak self] _ in
            Task { await self?.removeInbound(id) }
        }
        return stream
    }

    /// Subscribe to agent presence changes (online/offline).
    func presence() -> AsyncStream<AgentPresence> {
        var cont: AsyncStream<AgentPresence>.Continuation!
        let stream = AsyncStream<AgentPresence> { cont = $0 }
        let id = UUID()
        presenceConsumers[id] = cont
        cont.onTermination = { [weak self] _ in
            Task { await self?.removePresence(id) }
        }
        return stream
    }

    /// Subscribe to connection-state changes.  The current state is delivered
    /// immediately on subscribe, so late subscribers are not left in the dark.
    func states() -> AsyncStream<ConnectionState> {
        var cont: AsyncStream<ConnectionState>.Continuation!
        let stream = AsyncStream<ConnectionState> { cont = $0 }
        let id = UUID()
        stateConsumers[id] = cont
        cont.yield(connectionState)
        cont.onTermination = { [weak self] _ in
            Task { await self?.removeState(id) }
        }
        return stream
    }

    /// Subscribe to non-fatal error messages (decryption failures, transient
    /// transport errors) suitable for surfacing as a banner.
    func errors() -> AsyncStream<String> {
        var cont: AsyncStream<String>.Continuation!
        let stream = AsyncStream<String> { cont = $0 }
        let id = UUID()
        errorConsumers[id] = cont
        cont.onTermination = { [weak self] _ in
            Task { await self?.removeError(id) }
        }
        return stream
    }

    private func removeInbound(_ id: UUID)  { inboundConsumers[id] = nil }
    private func removePresence(_ id: UUID) { presenceConsumers[id] = nil }
    private func removeState(_ id: UUID)    { stateConsumers[id] = nil }
    private func removeError(_ id: UUID)    { errorConsumers[id] = nil }

    private func broadcast(_ payload: Payload) {
        for c in inboundConsumers.values { c.yield(payload) }
    }

    private func emitPresence(_ presence: AgentPresence) {
        for c in presenceConsumers.values { c.yield(presence) }
    }

    private func setState(_ state: ConnectionState) {
        connectionState = state
        for c in stateConsumers.values { c.yield(state) }
    }

    private func emitError(_ message: String) {
        for c in errorConsumers.values { c.yield(message) }
    }

    // MARK: - Small helpers

    private static func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    private static func beU64(_ v: UInt64) -> Data {
        var be = v.bigEndian
        return withUnsafeBytes(of: &be) { Data($0) }
    }

    private static func loadRecvCounter() -> UInt64 {
        guard let data = try? KeychainStore.shared.getData(for: KeychainStore.Key.recvCounter),
              data.count == 8 else { return 0 }
        var v: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &v) { data.copyBytes(to: $0) }
        return UInt64(bigEndian: v)
    }

    @MainActor
    private static func deviceInfo() -> DeviceInfo {
        DeviceInfo(
            platform: "ios",
            model: UIDevice.current.model,
            os_version: UIDevice.current.systemVersion,
            app_version: Bundle.main.appVersionString,
            device_name: UIDevice.current.name
        )
    }
}
