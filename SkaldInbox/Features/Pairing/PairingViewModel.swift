//
//  PairingViewModel.swift
//  Skald
//
//  Opens a one-shot `.pairing` WS to the relay, completes the challenge-
//  response, persists seed + namespace + agent pubkeys to Keychain, then
//  transitions AppState to `.awaitingAuth`.
//

import CryptoKit
import Foundation
import SwiftUI

@MainActor
final class PairingViewModel: ObservableObject {

    enum State: Equatable {
        case idle
        case connecting
        case awaitingConfirm
        case error(String)
    }

    @Published private(set) var state: State = .idle
    @Published private(set) var status: String = String(localized: "Ready")

    private weak var appState: AppState?
    private var currentTask: Task<Void, Never>?

    func attach(appState: AppState) {
        self.appState = appState
    }

    /// Kick off the pairing flow.  Safe to call multiple times — a previous
    /// attempt is cancelled.
    func performPairing(qrData: PairingQRData) {
        currentTask?.cancel()
        currentTask = Task { [weak self] in
            await self?.run(qrData: qrData)
        }
    }

    func cancel() {
        currentTask?.cancel()
        currentTask = nil
        state = .idle
        status = String(localized: "Cancelled")
    }

    // MARK: - Internals

    private func run(qrData: PairingQRData) async {
        guard let appState = appState else {
            state = .error(String(localized: "State not initialized"))
            return
        }

        // 1. Seed + derived keys.
        state = .connecting
        status = String(localized: "Loading credentials…")
        let seed: Data
        do {
            seed = try KeyManager.shared.loadOrCreateSeed()
        } catch {
            state = .error(String(localized: "Keychain: ") + error.localizedDescription)
            return
        }

        let keypair: SkaldKeypair
        do {
            keypair = try KeyManager.shared.deriveKeys(seed: seed)
        } catch {
            state = .error(String(localized: "Key derivation: ") + error.localizedDescription)
            return
        }

        // 2. namespace_id = SHA256(NS_DOMAIN ‖ 0x00 ‖ agent_ed25519_pub).
        let agentEd25519Pub: Data
        do {
            agentEd25519Pub = try Hex.decode(qrData.agent_ed25519_pub)
        } catch {
            state = .error(String(localized: "QR: invalid agent key"))
            return
        }
        let ns = KeyManager.shared.deriveNamespaceId(agentEd25519Pub: agentEd25519Pub)

        // 3. Build the RelayClient (role: .pairing).
        guard let url = URL(string: qrData.relay_url) else {
            state = .error(String(localized: "Invalid relay URL"))
            return
        }
        let client = RelayClient(
            relayURL: url,
            role: .pairing,
            namespaceIdHex: ns.hex,
            pairingTokenHex: qrData.pairing_token,
            clientEd25519Pub: Hex.encode(keypair.signing.publicKey.rawRepresentation),
            clientX25519Pub: Hex.encode(keypair.agreement.publicKey.rawRepresentation),
            agentEd25519Pub: qrData.agent_ed25519_pub,
            deviceToken: appState.deviceTokenHex
        )

        // 4. Open the WS, complete auth, persist, and close.
        status = String(localized: "Connecting to relay…")
        do {
            try await client.runClientSession(perform: nil)
        } catch let err as SkaldError {
            state = .error(err.errorDescription ?? String(localized: "Relay error"))
            return
        } catch {
            state = .error(error.localizedDescription)
            return
        }

        if Task.isCancelled { return }

        // 5. Persist every keychain entry.  Failures here are fatal — we
        // would otherwise end up in an inconsistent state.
        status = String(localized: "Saving credentials…")
        do {
            try persist(
                seed: seed,
                namespaceIdRaw: ns.raw,
                qrData: qrData,
                keypair: keypair
            )
        } catch {
            state = .error(String(localized: "Persist error: ") + error.localizedDescription)
            return
        }

        // 6. Hand off to AppState.
        status = String(localized: "Awaiting confirmation on Skald…")
        state = .awaitingConfirm
        appState.didCompletePairing(qrData: qrData)
    }

    private func persist(seed: Data,
                         namespaceIdRaw: Data,
                         qrData: PairingQRData,
                         keypair: SkaldKeypair) throws
    {
        let store = KeychainStore.shared
        try store.setData(seed, for: KeychainStore.Key.seed)
        try store.setData(namespaceIdRaw, for: KeychainStore.Key.namespaceId)
        try store.setString(qrData.relay_url, for: KeychainStore.Key.relayUrl)
        try store.setData(Hex.decode(qrData.agent_ed25519_pub), for: KeychainStore.Key.agentEd25519Pub)
        try store.setData(Hex.decode(qrData.agent_x25519_pub),  for: KeychainStore.Key.agentX25519Pub)
        try store.setData(keypair.signing.publicKey.rawRepresentation,           for: KeychainStore.Key.myEd25519Pub)
        try store.setData(keypair.agreement.publicKey.rawRepresentation,         for: KeychainStore.Key.myX25519Pub)

        // Reset both counters to 1 (the NEXT counter to use).
        try store.setData(Self.be(1), for: KeychainStore.Key.sendCounter)
        try store.setData(Self.be(1), for: KeychainStore.Key.recvCounter)

        // "hello" not sent yet.
        try store.delete(for: "skald.hello_sent")
    }

    /// Encode a UInt64 as 8 big-endian bytes.
    private static func be(_ v: UInt64) -> Data {
        var be = v.bigEndian
        return withUnsafeBytes(of: &be) { Data($0) }
    }
}
