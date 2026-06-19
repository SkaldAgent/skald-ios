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

    @Published private(set) var phase: AppState.Phase = .notPaired
    @Published private(set) var namespaceIdHex: String = ""
    @Published private(set) var agentEd25519PubTruncated: String = "—"
    @Published private(set) var myEd25519PubTruncated: String = "—"
    @Published private(set) var appVersion: String = "—"
    @Published private(set) var deviceName: String = "—"
    @Published private(set) var isLoggingOut: Bool = false

    private weak var appState: AppState?

    func attach(appState: AppState) {
        self.appState = appState
        refresh()
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
            let hex = Hex.encode(data)
            agentEd25519PubTruncated = Self.truncate(hex)
        }
        if let data = (try? KeychainStore.shared.getData(for: KeychainStore.Key.myEd25519Pub)) ?? nil,
           data.count == 32
        {
            let hex = Hex.encode(data)
            myEd25519PubTruncated = Self.truncate(hex)
        }

        appVersion = Bundle.main.appVersionString
        deviceName = UIDevice.current.name
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
