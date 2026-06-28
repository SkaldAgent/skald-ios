//
//  SettingsViewModel.swift
//  Skald
//
//  Loads the user's identity, namespace, and device info from Keychain
//  for the Settings screen.  `logout()` sends a best-effort E2E
//  `logout` payload to the agent and then wipes the Keychain.
//

import Foundation
import SwiftUI
import UIKit

@MainActor
final class SettingsViewModel: ObservableObject {

    /// One peer the relay reports as online in our namespace.  Identity is the
    /// raw Ed25519 pubkey; `kind` is derived by matching it against our own and
    /// the agent's keys (Option A — others are shown by fingerprint only).
    struct RosterDevice: Identifiable {
        enum Kind { case thisDevice, agent, other }

        /// Hex of the raw pubkey — stable identity for `ForEach`.
        let id: String
        let label: String
        /// Short, human-scannable fingerprint of the pubkey (e.g. `ab12cd…d7f0`).
        let fingerprint: String
        let kind: Kind
    }

    @Published private(set) var phase: AppState.Phase = .notPaired
    @Published private(set) var namespaceIdHex: String = ""
    @Published private(set) var agentEd25519PubTruncated: String = "—"
    @Published private(set) var myEd25519PubTruncated: String = "—"
    @Published private(set) var appVersion: String = "—"
    @Published private(set) var deviceName: String = "—"
    @Published private(set) var isLoggingOut: Bool = false
    /// Peers currently connected to the relay in our namespace, classified for
    /// display.  Empty while disconnected.
    @Published private(set) var devices: [RosterDevice] = []

    private weak var appState: AppState?

    /// Raw Ed25519 pubkeys used to classify roster entries.  Loaded once in
    /// `refresh()`; `nil` before we're paired.
    private var myEd25519Pub: Data?
    private var agentEd25519Pub: Data?

    /// The roster subscription.  Started once (the view calls `attach` on every
    /// `onAppear`), cancelled in `deinit`.
    private var rosterTask: Task<Void, Never>?

    func attach(appState: AppState) {
        self.appState = appState
        refresh()
        subscribeToRosterIfNeeded()
    }

    func refresh() {
        phase = appState?.phase ?? .notPaired

        if let ns = appState?.namespaceIdHex {
            namespaceIdHex = ns
        } else if let data = (try? KeychainStore.shared.getData(for: KeychainStore.Key.namespaceId)) ?? nil,
                  data.count == 32
        {
            namespaceIdHex = Hex.encode(data)
        } else {
            namespaceIdHex = ""
        }

        if let data = (try? KeychainStore.shared.getData(for: KeychainStore.Key.agentEd25519Pub)) ?? nil,
           data.count == 32
        {
            agentEd25519Pub = data
            agentEd25519PubTruncated = Self.truncate(Hex.encode(data))
        }
        if let data = (try? KeychainStore.shared.getData(for: KeychainStore.Key.myEd25519Pub)) ?? nil,
           data.count == 32
        {
            myEd25519Pub = data
            myEd25519PubTruncated = Self.truncate(Hex.encode(data))
        }

        appVersion = Bundle.main.appVersionString
        deviceName = UIDevice.current.name
    }

    // MARK: - Roster (namespace presence)

    private func subscribeToRosterIfNeeded() {
        guard rosterTask == nil, let session = appState?.session else { return }
        rosterTask = Task { [weak self] in
            for await peers in await session.roster() {
                self?.applyRoster(peers)
            }
        }
    }

    /// Map a roster snapshot (raw pubkeys) into classified, display-ordered
    /// `RosterDevice`s: this device first, then the agent, then everyone else by
    /// fingerprint.
    private func applyRoster(_ peers: [Data]) {
        let mapped: [RosterDevice] = peers.map { pub in
            let hex = Hex.encode(pub)
            let kind: RosterDevice.Kind
            let label: String
            if let mine = myEd25519Pub, pub == mine {
                kind = .thisDevice
                label = String(localized: "This device")
            } else if let agent = agentEd25519Pub, pub == agent {
                kind = .agent
                label = "Skald"
            } else {
                kind = .other
                label = String(localized: "Device")
            }
            return RosterDevice(
                id: hex,
                label: label,
                fingerprint: Self.fingerprint(hex),
                kind: kind
            )
        }
        devices = mapped.sorted { Self.order($0.kind) < Self.order($1.kind) }
    }

    private static func order(_ kind: RosterDevice.Kind) -> Int {
        switch kind {
        case .thisDevice: return 0
        case .agent:      return 1
        case .other:      return 2
        }
    }

    /// `ab12cd…89d7f0` — first 6 and last 6 hex chars of the pubkey.
    private static func fingerprint(_ hex: String) -> String {
        guard hex.count > 14 else { return hex }
        return "\(hex.prefix(6))…\(hex.suffix(6))"
    }

    deinit {
        rosterTask?.cancel()
    }

    /// Best-effort E2E `logout` + Keychain wipe, then transition AppState back
    /// to `.notPaired`.  All the heavy lifting (send, tear-down, wipe) lives in
    /// `SkaldSession.logout`.
    func logout() async {
        guard !isLoggingOut else { return }
        isLoggingOut = true
        defer { isLoggingOut = false }

        await appState?.session.logout()
        appState?.didLogout()
    }

    // MARK: - Internals

    private static func truncate(_ hex: String) -> String {
        guard hex.count > 12 else { return hex }
        let head = String(hex.prefix(12))
        return "\(head)…"
    }
}
