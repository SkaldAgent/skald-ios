//
//  InboxViewModel.swift
//  Skald
//
//  Inbox UI state.  Subscribes to the shared `SkaldSession` for decrypted
//  payloads, connection state, presence and errors, and translates the
//  `inbox_update` snapshots into the lists the view renders.  All transport,
//  crypto and reconnect concerns live in `SkaldSession` — this view-model is
//  pure inbox domain + UI.
//

import Foundation
import os.log
import SwiftUI

@MainActor
final class InboxViewModel: ObservableObject {

    // MARK: - Public state

    enum ConnectionState: Equatable { case disconnected, connecting, connected }

    @Published private(set) var approvals: [ApprovalItem] = []
    @Published private(set) var clarifications: [ClarificationItem] = []
    @Published private(set) var elicitations: [ElicitationItem] = []
    @Published private(set) var badge: Int = 0
    @Published private(set) var connectionState: ConnectionState = .disconnected

    /// True while a user-initiated pull-to-refresh is in flight.  Drives the
    /// "Refreshing…" overlay in `InboxView`.
    @Published private(set) var isRefreshing: Bool = false

    @Published var lastError: String?

    /// Bumped externally (e.g. from SettingsView) to make the view re-fetch
    /// the latest state.  Currently unused but kept as an extension point.
    @Published var refreshTick: Int = 0

    // MARK: - Wiring

    private weak var appState: AppState?
    private var session: SkaldSession?

    /// Agent presence — optimistic on a fresh session (matches V1 behaviour).
    /// Flipped to `false` on `PeerOffline`/`PresenceEvent{OFFLINE}` for the
    /// agent, back to `true` on `ONLINE`.  The `inbox_request` re-send on
    /// `ONLINE` is gated on this flag (relay-protocol.md v2 §4).
    private var agentOnline: Bool = true

    /// Timestamp of the last received `inbox_update`.  Used by `refresh()` to
    /// detect a response even when counts haven't changed (e.g. empty inbox).
    private var lastInboxUpdateAt: Date?

    /// Long-lived subscriptions to the session's streams.  Cancelled on deinit.
    private var subscriptions: [Task<Void, Never>] = []

    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "InboxVM")

    /// Attach to the app-wide state and subscribe to the shared session's
    /// streams.  Idempotent — safe to call from `.task` on every view rebuild.
    func attach(appState: AppState) {
        self.appState = appState
        guard session == nil else { return }
        let session = appState.session
        self.session = session
        subscribe(to: session)
    }

    private func subscribe(to session: SkaldSession) {
        subscriptions.append(Task { [weak self] in
            for await state in await session.states() {
                await self?.handle(state: state)
            }
        })
        subscriptions.append(Task { [weak self] in
            for await payload in await session.inbound() {
                self?.applyPayload(payload)
            }
        })
        subscriptions.append(Task { [weak self] in
            for await presence in await session.presence() {
                await self?.handle(presence: presence)
            }
        })
        subscriptions.append(Task { [weak self] in
            for await message in await session.errors() {
                self?.lastError = message
            }
        })
    }

    deinit {
        subscriptions.forEach { $0.cancel() }
    }

    // MARK: - Lifecycle

    /// Start (or resume) the shared session.  Idempotent.
    func connect() {
        guard let appState = appState, appState.phase != .notPaired else { return }
        guard let session = session else { return }
        Task { await session.start() }
    }

    /// Stop the shared session.  Safe to call when already stopped.
    func disconnect() {
        connectionState = .disconnected
        guard let session = session else { return }
        Task { await session.stop() }
    }

    // MARK: - Session stream handlers

    private func handle(state: SkaldSession.ConnectionState) async {
        switch state {
        case .connecting:
            connectionState = .connecting
        case .connected:
            connectionState = .connected
            agentOnline = true
            appState?.handleAuthOk()
            // Every (re)connection: ask the agent for a fresh `inbox_update`
            // (payloads.md §4.6).  Sent live — if the agent is offline the
            // relay replies `PeerOffline` and the next `ONLINE` triggers a retry.
            await sendInboxRequest()
        case .disconnected:
            connectionState = .disconnected
            appState?.handleDisconnected()
        case .unauthorized:
            connectionState = .disconnected
            appState?.handleAuthError(.relayError("unauthorized"))
        }
    }

    private func handle(presence: SkaldSession.AgentPresence) async {
        switch presence {
        case .online:
            if !agentOnline {
                log.info("agent ONLINE; re-sending inbox_request")
                agentOnline = true
                await sendInboxRequest()
            }
        case .offline:
            agentOnline = false
        }
    }

    // MARK: - Refresh (pull-to-refresh)

    /// Saves a snapshot of the current inbox state, fires an `inbox_request` on
    /// the live channel, then polls up to ~5s for a fresh `inbox_update`.  If
    /// nothing arrives the agent is probably offline — surface that.
    func refresh() async {
        isRefreshing = true
        let startedAt = Date()
        let minVisibleDuration: TimeInterval = 0.6

        let snapshotUpdateAt = lastInboxUpdateAt
        await sendInboxRequest()
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
        guard let session = session else { return }
        let payload = ClarificationResponse(
            v: 1,
            kind: "clarification_response",
            id: UUID().uuidString.lowercased(),
            ts: Self.nowMillis(),
            request_id: item.request_id,
            answer: answer
        )
        do {
            try await session.send(payload)
            applyLocalRemoveClarification(requestId: item.request_id)
        } catch {
            lastError = String(localized: "Send answer: ") + error.localizedDescription
        }
    }

    private func sendDecision(item: ApprovalItem, decision: String, reason: String?) async {
        guard let session = session else { return }
        let payload = ApprovalResponse(
            v: 1,
            kind: "approval_response",
            id: UUID().uuidString.lowercased(),
            ts: Self.nowMillis(),
            request_id: item.request_id,
            decision: decision,
            reason: reason
        )
        do {
            try await session.send(payload)
            applyLocalRemoveApproval(requestId: item.request_id)
        } catch {
            lastError = String(localized: "Send decision: ") + error.localizedDescription
        }
    }

    // MARK: - Elicitations (MCP secret input)

    /// Accept an MCP elicitation.  For an input prompt pass the typed `value`
    /// (sealed E2E, never logged); for a confirmation pass `nil`.  The value is
    /// keyed by the elicitation's `field_name` (fallback `"value"`).
    func acceptElicitation(_ item: ElicitationItem, value: String?) async {
        var content: [String: String]?
        if let value = value {
            content = [(item.field_name ?? "value"): value]
        }
        await sendElicitation(item: item, action: "accept", content: content)
    }

    /// Decline an MCP elicitation (`action: "decline"`, no content).
    func declineElicitation(_ item: ElicitationItem) async {
        await sendElicitation(item: item, action: "decline", content: nil)
    }

    private func sendElicitation(item: ElicitationItem, action: String, content: [String: String]?) async {
        guard let session = session else { return }
        let payload = ElicitationResponse(
            v: 1,
            kind: "elicitation_response",
            id: UUID().uuidString.lowercased(),
            ts: Self.nowMillis(),
            request_id: item.request_id,
            action: action,
            content: content
        )
        do {
            try await session.send(payload)
            applyLocalRemoveElicitation(requestId: item.request_id)
        } catch {
            // Never include `content`/value in the surfaced error.
            lastError = String(localized: "Send response: ") + error.localizedDescription
        }
    }

    // MARK: - Outgoing inbox_request

    private func sendInboxRequest() async {
        guard let session = session else { return }
        let payload = InboxRequest(
            v: 1,
            kind: "inbox_request",
            id: UUID().uuidString.lowercased(),
            ts: Self.nowMillis()
        )
        try? await session.send(payload, live: true)
    }

    // MARK: - Apply payloads

    private func applyPayload(_ payload: Payload) {
        switch payload {
        case .inboxUpdate(let u):
            approvals = u.approvals
            clarifications = u.clarifications
            elicitations = u.elicitations ?? []
            badge = u.badge
            lastInboxUpdateAt = Date()
        case .notification, .ack, .hello, .inboxRequest, .approvalResponse, .clarificationResponse, .elicitationResponse, .logout:
            // We don't act on these (acks are informational; the rest are our
            // own outgoing messages that the relay echoes back).
            break
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

    private func applyLocalRemoveElicitation(requestId: String) {
        elicitations.removeAll { $0.request_id == requestId }
        if badge > 0 { badge -= 1 }
    }

    // MARK: - Helpers

    private static func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
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

extension ElicitationItem: Identifiable {
    var id: String { request_id }
}
