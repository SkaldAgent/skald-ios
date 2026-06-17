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

    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "InboxVM")

    func attach(appState: AppState) {
        self.appState = appState
    }

    // MARK: - Lifecycle

    /// Start (or restart) the WS session.  Idempotent — multiple calls just
    /// cancel the previous task and start a new one with fresh backoff.
    func connect() {
        guard let appState = appState, appState.phase != .notPaired else { return }
        sessionTask?.cancel()
        connectionState = .connecting
        sessionTask = Task { [weak self] in
            await self?.runSessionLoop()
        }
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
    /// `backoff(n)` seconds (1, 2, 4, …, 60 + jitter) and try again.  Stops
    /// when `disconnect()` cancels the surrounding `Task`.
    private func runSessionLoop() async {
        var attempt = 0
        while !Task.isCancelled {
            attempt += 1
            do {
                try await runOneSession()
                // Clean exit (no error) — reset the backoff.
                attempt = 0
            } catch is CancellationError {
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

            // Exponential backoff with ±20% jitter, capped at 60s.
            let base = min(60, 1 << min(attempt - 1, 5))
            let jitter = Double.random(in: 0.8...1.2)
            let delay = Double(base) * jitter
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

            // Drive the receive loop until the task is cancelled or the WS
            // errors.  The closure is @Sendable; we hop to the main actor
            // before mutating @Published state.
            let weakSelf = self
            await c.receiveLoop(
                onMessage: { msg in
                    await weakSelf.handleIncoming(msg)
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
            let nonce = try Hex.decode(msg.nonce)
            let sealed = try Base64.decode(msg.ciphertext)
            let from = try Hex.decode(msg.from)

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

    private func applyPayload(_ payload: Payload) {
        switch payload {
        case .inboxUpdate(let u):
            approvals = u.approvals
            clarifications = u.clarifications
            badge = u.badge
        case .notification, .ack, .hello, .approvalResponse, .clarificationResponse, .logout:
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
