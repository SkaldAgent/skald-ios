//
//  InboxViewModel.swift
//  Skald
//
//  Owns the long-lived `.client` WS session.  Sends and receives E2E
//  payloads, applies `inbox_update` snapshots to the UI state, and handles
//  automatic reconnection with exponential backoff.
//

import CryptoKit
import Foundation
import os.log
import SwiftUI
import UIKit

@MainActor
final class InboxViewModel: ObservableObject {

    // MARK: - Public state

    enum ConnectionState: Equatable { case disconnected, connecting, connected }

    @Published private(set) var approvals: [ApprovalItem] = []
    @Published private(set) var clarifications: [ClarificationItem] = []
    @Published private(set) var badge: Int = 0
    @Published private(set) var connectionState: ConnectionState = .disconnected

    /// True while a user-initiated pull-to-refresh is in flight.  Drives the
    /// "Refreshing…" overlay in `InboxView` and is used (together with a
    /// minimum visible duration inside `refresh()`) to make the
    /// `.refreshable` gesture feel responsive.
    @Published private(set) var isRefreshing: Bool = false

    @Published var lastError: String?

    /// Bumped externally (e.g. from SettingsView) to make the view re-fetch
    /// the latest state.  Currently unused but kept as an extension point.
    @Published var refreshTick: Int = 0

    // MARK: - Wiring

    private weak var appState: AppState?
    private var sessionTask: Task<Void, Never>?

    /// Cached engine — recreated on every (re)connect from Keychain.
    private var cryptoEngine: CryptoEngine?

    /// The active RelayClient (or nil if disconnected).  Held so that the
    /// `approve/reject/answer` methods can `await` on it.
    private var currentClient: RelayClient?

    /// Last-seen receive counter (mirrored to Keychain after every open).
    private var recvCounter: UInt64 = 0

    /// Agent presence — optimistic on a fresh session (matches V1 behaviour).
    /// Flipped to `false` when we get `PeerOffline` or `PresenceEvent{OFFLINE}`
    /// for the agent, back to `true` on `PresenceEvent{ONLINE}`.  The
    /// `inbox_request` re-send on `ONLINE` is gated on this flag
    /// (relay-protocol.md v2 §4).
    private var agentOnline: Bool = true

    /// Timestamp of the last received `inbox_update`. Used by `refresh()` to
    /// detect a response even when counts haven't changed (e.g. empty inbox).
    private var lastInboxUpdateAt: Date?

    /// Raw 32B ed25519 pub of the agent — cached on every `runOneSession`
    /// from Keychain and used to filter `PresenceEvent`s to "is this the
    /// agent, or some other peer in the namespace?"
    private var agentEd25519Pub: Data?

    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "InboxVM")

    func attach(appState: AppState) {
        self.appState = appState
        // When the APNs token arrives/rotates after we're already connected,
        // tear down and reopen the session so the relay re-learns the token.
        appState.onDeviceTokenChanged = { [weak self] in
            Task { @MainActor in self?.reconnect() }
        }
    }

    // MARK: - Lifecycle

    /// Start (or restart) the WS session.  Idempotent — multiple calls just
    /// cancel the previous task and start a new one with fresh backoff.
    func connect() {
        guard let appState = appState, appState.phase != .notPaired else { return }
        // Don't start a new session if we're already connected or connecting.
        if connectionState == .connected || connectionState == .connecting { return }
        sessionTask?.cancel()
        connectionState = .connecting
        sessionTask = Task { [weak self] in
            await self?.runSessionLoop()
        }
    }

    /// Force a fresh session: cancel the current one and reconnect. Used when
    /// the APNs device token arrives or rotates after we already authenticated,
    /// so the relay handshake re-sends the new token.
    func reconnect() {
        guard let appState = appState, appState.phase != .notPaired else { return }
        sessionTask?.cancel()
        sessionTask = nil
        let client = currentClient
        currentClient = nil
        Task { await client?.close() }
        connectionState = .disconnected
        connect()
    }

    /// Stop the WS session.  Safe to call when already stopped.
    func disconnect() {
        sessionTask?.cancel()
        sessionTask = nil
        connectionState = .disconnected
        let client = currentClient
        currentClient = nil
        Task { await client?.close() }
        appState?.handleDisconnected()
    }

    /// Manual refresh hook (pull-to-refresh).  Saves a snapshot of the current
    /// inbox state, fires an `inbox_request` on the live channel, then polls
    /// for up to ~5s waiting for a fresh `inbox_update` to land.  If nothing
    /// arrives the agent is probably offline — surface that as `lastError`.
    /// The session loop handles automatic reconnection, so this is purely a
    /// user-initiated nudge.
    ///
    /// `isRefreshing` is held true for the whole call, and the call is
    /// stretched to at least ~0.6s of wall-clock time.  Without that floor
    /// the system `.refreshable` spinner (and the "Refreshing…" overlay) can
    /// flash by in <200ms when an `inbox_update` lands on the first poll,
    /// making the pull-to-refresh gesture feel unresponsive.
    func refresh() async {
        isRefreshing = true
        let startedAt = Date()
        let minVisibleDuration: TimeInterval = 0.6

        let snapshotUpdateAt = lastInboxUpdateAt
        await sendInboxRequest()
        // Poll up to 25 × 200ms ≈ 5s for `applyPayload(.inboxUpdate)` to
        // land.  We track the timestamp of the last update rather than
        // comparing counts, so an agent that correctly responds with an
        // unchanged (e.g. empty) inbox is not misreported as offline.
        var didChange = false
        for _ in 0..<25 {
            try? await Task.sleep(nanoseconds: 200_000_000)
            if lastInboxUpdateAt != snapshotUpdateAt {
                didChange = true
                break
            }
        }
        if !didChange {
            lastError = String(localized: "Agent offline or timeout")
        }
        // Hold the spinner / banner for at least `minVisibleDuration` so the
        // refresh feedback is actually noticeable.  When the underlying work
        // already exceeded the budget this is a no-op.
        let elapsed = Date().timeIntervalSince(startedAt)
        let remaining = minVisibleDuration - elapsed
        if remaining > 0 {
            try? await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
        }
        isRefreshing = false
    }

    // MARK: - Approvals / Rejections / Answers

    func approve(_ item: ApprovalItem) async {
        await sendDecision(item: item, decision: "approved", reason: nil)
    }

    func reject(_ item: ApprovalItem, reason: String) async {
        await sendDecision(item: item, decision: "rejected", reason: reason)
    }

    func answer(_ item: ClarificationItem, answer: String) async {
        guard let client = currentClient, let engine = cryptoEngine else { return }
        let payload = ClarificationResponse(
            v: 1,
            kind: "clarification_response",
            id: UUID().uuidString.lowercased(),
            ts: Int64(Date().timeIntervalSince1970 * 1000),
            request_id: item.request_id,
            answer: answer
        )
        do {
            let data = try JSONEncoder().encode(payload)
            try await client.sendE2E(plaintext: data, cryptoEngine: engine)
            applyLocalRemoveClarification(requestId: item.request_id)
        } catch {
            lastError = String(localized: "Send answer: ") + error.localizedDescription
        }
    }

    // MARK: - Session loop

    /// Outer loop: open a session, run the receive loop, on exit wait
    /// `backoff(n)` seconds (1, 2, 4, …, 32 + jitter) and try again.  Stops
    /// only when `disconnect()` cancels the surrounding `Task`
    /// (relay-protocol.md v2 §8: the client reconnects with backoff).
    private func runSessionLoop() async {
        var attempt = 0
        while !Task.isCancelled {
            let startedAt = Date()
            do {
                try await runOneSession()
                // `runOneSession` only returns once the receive loop ended:
                // either `disconnect()` cancelled us, or the WS dropped
                // underneath us. The receive loop reports transport errors via
                // its `onError` callback and returns normally (it does NOT
                // throw), so a network drop lands here — NOT in the catch
                // blocks below. We must therefore treat a clean return as a
                // disconnect that needs reconnecting, unless we were cancelled.
                if Task.isCancelled {
                    connectionState = .disconnected
                    return
                }
                // WS dropped while still wanted → fall through to backoff.
            } catch is CancellationError {
                connectionState = .disconnected
                return
            } catch let err as SkaldError {
                lastError = err.errorDescription
                // Auth failures during awaiting → bail out, let AppState
                // decide whether to flip back to .notPaired.
                if case .relayError(let msg) = err, msg.contains("unauthorized") {
                    appState?.handleAuthError(err)
                    return
                }
                // Other errors: keep retrying.
            } catch {
                lastError = error.localizedDescription
            }
            connectionState = .disconnected
            appState?.handleDisconnected()

            if Task.isCancelled { return }

            // A session that stayed up for a while was "healthy": reset the
            // backoff so the next drop reconnects quickly. A session that died
            // almost immediately keeps climbing the backoff, avoiding a hot
            // reconnect loop against a relay that's down or rejecting us.
            if Date().timeIntervalSince(startedAt) > 30 {
                attempt = 0
            }

            // Exponential backoff with ±20% jitter, capped at 32s.
            let base = min(60, 1 << min(attempt, 5))
            let jitter = Double.random(in: 0.8...1.2)
            let delay = Double(base) * jitter
            attempt += 1
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    }

    /// One WS session: open, build engine, send hello (if first), drive the
    /// receive loop, then return.
    private func runOneSession() async throws {
        guard let appState = appState else { return }
        guard let nsHex = appState.namespaceIdHex,
              let myEd = appState.myEd25519PubHex,
              let myX  = appState.myX25519PubHex,
              let relayURLString = try? KeychainStore.shared.getString(for: KeychainStore.Key.relayUrl),
              let relayURL = URL(string: relayURLString),
              let agentEd = try? KeychainStore.shared.getData(for: KeychainStore.Key.agentEd25519Pub)
        else {
            throw SkaldError.invalidPayload
        }

        let client = RelayClient(
            relayURL: relayURL,
            role: .client,
            namespaceIdHex: nsHex,
            pairingTokenHex: nil,
            clientEd25519Pub: myEd,
            clientX25519Pub: myX,
            agentEd25519Pub: Hex.encode(agentEd),
            deviceToken: appState.deviceTokenHex
        )
        self.currentClient = client
        // Cache the raw 32B agent ed25519 pub for presence-event filtering.
        self.agentEd25519Pub = agentEd

        // Build the engine up front (needs the session to be authenticated
        // by the relay, but the engine itself is just a key-derivation
        // helper — no network involved).
        self.cryptoEngine = try Self.makeEngine()
        if let data = try? KeychainStore.shared.getData(for: KeychainStore.Key.recvCounter),
           data.count == 8
        {
            self.recvCounter = Self.readBE(data)
        } else {
            self.recvCounter = 0
        }

        try await client.runClientSession { [weak self] c in
            guard let self = self else { return }
            self.connectionState = .connected
            self.appState?.handleAuthOk()

            // First connect: send a `hello` so the agent learns our device info.
            if (try? KeychainStore.shared.getString(for: "skald.hello_sent")) == nil,
               let engine = self.cryptoEngine
            {
                let payload = Hello(
                    v: 1,
                    kind: "hello",
                    id: UUID().uuidString.lowercased(),
                    ts: Int64(Date().timeIntervalSince1970 * 1000),
                    device_info: DeviceInfo(
                        platform: "ios",
                        model: UIDevice.current.model,
                        os_version: UIDevice.current.systemVersion,
                        app_version: Bundle.main.appVersionString,
                        device_name: UIDevice.current.name
                    )
                )
                if let data = try? JSONEncoder().encode(payload) {
                    try? await c.sendE2E(plaintext: data, cryptoEngine: engine)
                    try? KeychainStore.shared.setString("1", for: "skald.hello_sent")
                }
            }

            // Every (re)connection: ask the agent for a fresh targeted
            // `inbox_update` snapshot (payloads.md §4.6, v2/relay-protocol.md
            // §3.1).  Sent on the live channel: if the agent is offline the
            // relay responds with `PeerOffline` and the next
            // `PresenceEvent{ONLINE}` triggers a retry.
            await self.sendInboxRequest()

            // Drive the receive loop until the task is cancelled or the WS
            // errors.  The closure is @Sendable; we hop to the main actor
            // before mutating @Published state.
            let weakSelf = self
            await c.receiveLoop(
                onMessage: { msg in
                    await weakSelf.handleIncoming(msg)
                },
                onPeerOffline: { notice in
                    await weakSelf.handlePeerOffline(notice)
                },
                onPresenceEvent: { event in
                    await weakSelf.handlePresenceEvent(event)
                },
                onError: { err in
                    let descr = (err as? SkaldError)?.errorDescription
                        ?? err.localizedDescription
                    Task { @MainActor in
                        weakSelf.lastError = descr
                    }
                }
            )
        }
    }

    // MARK: - Receive handling

    private func handleIncoming(_ msg: IncomingMessage) async {
        guard let engine = cryptoEngine else { return }
        guard let myEd = appState?.myEd25519Pub else { return }

        do {
            // V2: all crypto envelope fields are raw bytes end-to-end
            // (relay-protocol.md v2 §1).  No more hex/base64 decoding.
            let nonce = msg.nonce
            let sealed = msg.ciphertext
            let from = msg.from

            let plaintext = try engine.open(
                nonce: nonce,
                sealed: sealed,
                direction: CryptoConstants.nonceDirAgentToClient,
                lastSeenCounter: { [weak self] in self?.recvCounter ?? 0 },
                updateLastSeen: { [weak self] newValue in
                    guard let self = self else { return }
                    self.recvCounter = newValue
                    if let advanced = try? KeychainStore.shared.compareAndAdvanceCounter(
                        for: KeychainStore.Key.recvCounter,
                        to: newValue
                    ) {
                        self.recvCounter = advanced
                    }
                },
                fromEd25519Pub: from,
                toEd25519Pub: myEd
            )

            let payload = try JSONDecoder().decode(Payload.self, from: plaintext)
            applyPayload(payload)
        } catch let err as SkaldError {
            lastError = String(localized: "Decryption: ") + (err.errorDescription ?? String(localized: "unknown error"))
        } catch {
            lastError = String(localized: "Decryption: ") + error.localizedDescription
        }
    }

    // MARK: - Live-channel handlers (relay-protocol.md v2 §3, §4)

    /// `PeerOffline{peer}` from the relay: the agent was offline when we
    /// tried to `sendE2E(..., live: true)`, so the message was NOT queued
    /// and NOT pushed.  Don't try to send again until we see
    /// `PresenceEvent{ONLINE}` for the agent.
    private func handlePeerOffline(_ notice: PeerOfflineNotice) async {
        log.info("peer_offline received; marking agent offline")
        agentOnline = false
    }

    /// A presence status change from the relay.  We only act on events
    /// about the agent itself (not us, not other devices in the namespace).
    /// On `ONLINE` we re-send the `inbox_request` so the agent's next
    /// `inbox_update` lands on us immediately.
    private func handlePresenceEvent(_ event: PresenceEventInfo) async {
        // Filter to events about the agent.
        guard let agentEd = agentEd25519Pub, !agentEd.isEmpty,
              event.pubkey == agentEd else { return }
        switch event.status {
        case .online:
            if !agentOnline {
                log.info("PresenceEvent{ONLINE} for agent; re-sending inbox_request")
                agentOnline = true
                await sendInboxRequest()
            } else {
                // Idempotent: two ONLINE events in a row is a no-op.
                log.debug("PresenceEvent{ONLINE} for agent already; ignoring")
            }
        case .offline:
            log.info("PresenceEvent{OFFLINE} for agent")
            agentOnline = false
        case .other:
            // Unknown status value: ignore.
            break
        }
    }

    /// Send a fresh `inbox_request` on the live channel.  Called on
    /// (re)connect and on `PresenceEvent{ONLINE}` for the agent.
    private func sendInboxRequest() async {
        guard let client = currentClient, let engine = cryptoEngine else { return }
        let payload = InboxRequest(
            v: 1,
            kind: "inbox_request",
            id: UUID().uuidString.lowercased(),
            ts: Int64(Date().timeIntervalSince1970 * 1000)
        )
        if let data = try? JSONEncoder().encode(payload) {
            try? await client.sendE2E(plaintext: data, cryptoEngine: engine, live: true)
        }
    }

    private func applyPayload(_ payload: Payload) {
        switch payload {
        case .inboxUpdate(let u):
            approvals = u.approvals
            clarifications = u.clarifications
            badge = u.badge
            lastInboxUpdateAt = Date()
        case .notification, .ack, .hello, .inboxRequest, .approvalResponse, .clarificationResponse, .logout:
            // We don't act on these (acks are informational; the rest are
            // our own outgoing messages that the relay echoes back).
            break
        }
    }

    // MARK: - Outgoing decision

    private func sendDecision(item: ApprovalItem, decision: String, reason: String?) async {
        guard let client = currentClient, let engine = cryptoEngine else { return }
        let payload = ApprovalResponse(
            v: 1,
            kind: "approval_response",
            id: UUID().uuidString.lowercased(),
            ts: Int64(Date().timeIntervalSince1970 * 1000),
            request_id: item.request_id,
            decision: decision,
            reason: reason
        )
        do {
            let data = try JSONEncoder().encode(payload)
            try await client.sendE2E(plaintext: data, cryptoEngine: engine)
            applyLocalRemoveApproval(requestId: item.request_id)
        } catch {
            lastError = String(localized: "Send decision: ") + error.localizedDescription
        }
    }

    private func applyLocalRemoveApproval(requestId: String) {
        approvals.removeAll { $0.request_id == requestId }
        if badge > 0 { badge -= 1 }
    }

    private func applyLocalRemoveClarification(requestId: String) {
        clarifications.removeAll { $0.request_id == requestId }
        if badge > 0 { badge -= 1 }
    }

    // MARK: - Engine factory

    private static func makeEngine() throws -> CryptoEngine {
        let seed = try KeyManager.shared.loadOrCreateSeed()
        let kp = try KeyManager.shared.deriveKeys(seed: seed)
        let agentEd = try Self.require(KeychainStore.Key.agentEd25519Pub)
        let agentX  = try Self.require(KeychainStore.Key.agentX25519Pub)
        let ns      = try Self.require(KeychainStore.Key.namespaceId)
        return CryptoEngine(
            agentX25519Pub:  agentX,
            agentEd25519Pub: agentEd,
            myX25519Priv:    kp.agreement,
            myEd25519Pub:    kp.signing.publicKey.rawRepresentation,
            namespaceIdRaw:  ns
        )
    }

    private static func require(_ account: String) throws -> Data {
        do {
            guard let d = try KeychainStore.shared.getData(for: account), d.count == 32 else {
                throw SkaldError.invalidPayload
            }
            return d
        } catch let e as SkaldError {
            throw e
        } catch {
            throw SkaldError.invalidPayload
        }
    }

    // MARK: - Counter helpers

    private static func readBE(_ data: Data) -> UInt64 {
        guard data.count == 8 else { return 0 }
        var v: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &v) { dst in
            data.copyBytes(to: dst)
        }
        return UInt64(bigEndian: v)
    }
}

// MARK: - Bundle helper

extension Bundle {
    var appVersionString: String {
        let short = (infoDictionary?["CFBundleShortVersionString"] as? String) ?? "?"
        let build = (infoDictionary?["CFBundleVersion"] as? String) ?? "?"
        return "\(short) (\(build))"
    }
}

// MARK: - Identifiable conformance

extension ApprovalItem: Identifiable {
    var id: String { request_id }
}

extension ClarificationItem: Identifiable {
    var id: String { request_id }
}
