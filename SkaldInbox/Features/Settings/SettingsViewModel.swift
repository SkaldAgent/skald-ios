//
//  SettingsViewModel.swift
//  Skald
//
//  Loads the user's identity, namespace, and device info from Keychain
//  for the Settings screen.  `logout()` sends a best-effort E2E
//  `logout` payload to the agent and then wipes the Keychain.
//

import CryptoKit
import Foundation
import os.log
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
    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "Settings")

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

    /// Send a best-effort E2E `logout` (5s timeout) and then wipe the
    /// Keychain.  The AppState transitions back to `.notPaired` once
    /// everything is clean.
    func logout() async {
        guard !isLoggingOut else { return }
        isLoggingOut = true
        defer { isLoggingOut = false }

        await withTaskGroup(of: Void.self) { group in
            group.addTask { [weak self] in
                await self?.sendLogoutE2E()
            }
            // 5-second cap on the whole best-effort send.
            group.addTask {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
            await group.next()
            group.cancelAll()
        }

        do {
            try KeychainStore.shared.deleteAll()
        } catch {
            // Even if Keychain deletion fails, transition state — the user
            // expects to be logged out.  Log it: a silent failure here used to
            // leave the pairing on-device, so logout looked broken.
            log.error("Keychain wipe on logout failed: \(String(describing: error), privacy: .public)")
        }
        appState?.didLogout()
    }

    // MARK: - Internals

    private func sendLogoutE2E() async {
        guard let appState = appState,
              let nsHex = appState.namespaceIdHex,
              let myEd = appState.myEd25519PubHex,
              let myX  = appState.myX25519PubHex,
              let relayURLString = try? KeychainStore.shared.getString(for: KeychainStore.Key.relayUrl),
              let relayURL = URL(string: relayURLString),
              let agentEd = try? KeychainStore.shared.getData(for: KeychainStore.Key.agentEd25519Pub)
        else { return }

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

        do {
            try await client.runClientSession { c in
                let engine = try Self.makeEngine()
                let payload = LogoutPayload(
                    v: 1,
                    kind: "logout",
                    id: UUID().uuidString.lowercased(),
                    ts: Int64(Date().timeIntervalSince1970 * 1000)
                )
                let data = try JSONEncoder().encode(payload)
                try await c.sendE2E(plaintext: data, cryptoEngine: engine)
            }
        } catch {
            // Best-effort: ignore failures.
        }
    }

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

    private static func truncate(_ hex: String) -> String {
        guard hex.count > 12 else { return hex }
        let head = String(hex.prefix(12))
        return "\(head)…"
    }
}
