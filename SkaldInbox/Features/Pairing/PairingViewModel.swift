//
//  PairingViewModel.swift
//  Skald
//
//  Opens a one-shot `.pairing` WS to the relay, completes the challenge-
//  response, persists seed + namespace + agent pubkeys to Keychain, then
//  transitions AppState to `.awaitingAuth`.
//

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

    /// Resume an in-progress pairing: credentials are already persisted (we're
    /// in `.awaitingAuth`), so connect as the `.client` and wait for the agent
    /// to authorise this device.  The relay replies `unauthorized` until then —
    /// `startAwaitingAuthorization` keeps retrying with backoff (relay-protocol
    /// §4.2).  The first `.connected` means we're authorised: hand off to
    /// `AppState`, which swaps the root to the inbox.
    func awaitConfirmation() {
        guard let appState = appState else {
            state = .error(String(localized: "State not initialized"))
            return
        }
        currentTask?.cancel()
        state = .awaitingConfirm
        status = String(localized: "Awaiting confirmation on Skald…")
        let session = appState.session
        currentTask = Task { [weak self] in
            await session.startAwaitingAuthorization()
            for await connState in await session.states() {
                if Task.isCancelled { return }
                switch connState {
                case .connected:
                    self?.appState?.handleAuthOk()
                    return
                case .unauthorized:
                    // Not expected while awaiting (the session retries through
                    // it), but surface it defensively rather than hang.
                    self?.state = .error(String(localized: "Authorization failed"))
                    return
                case .connecting, .disconnected:
                    continue
                }
            }
        }
    }

    func cancel() {
        currentTask?.cancel()
        currentTask = nil
        state = .idle
        status = String(localized: "Cancelled")
        // Tear the client session down so it doesn't keep retrying in the
        // background after we return to the scan screen.
        if let session = appState?.session {
            Task { await session.stop() }
        }
    }

    // MARK: - Internals

    /// Open a `.pairing` WS via the shared session, which completes the
    /// challenge/response and persists all credentials, then hand off to
    /// `AppState`.  All crypto + persistence lives in `SkaldSession.pair`.
    private func run(qrData: PairingQRData) async {
        guard let appState = appState else {
            state = .error(String(localized: "State not initialized"))
            return
        }

        state = .connecting
        status = String(localized: "Connecting to relay…")
        do {
            try await appState.session.pair(qrData)
        } catch let err as SkaldError {
            state = .error(err.errorDescription ?? String(localized: "Relay error"))
            return
        } catch {
            state = .error(error.localizedDescription)
            return
        }

        if Task.isCancelled { return }

        status = String(localized: "Awaiting confirmation on Skald…")
        state = .awaitingConfirm
        appState.didCompletePairing(qrData: qrData)
    }
}
