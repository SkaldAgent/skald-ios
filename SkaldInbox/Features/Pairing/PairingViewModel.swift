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

    func cancel() {
        currentTask?.cancel()
        currentTask = nil
        state = .idle
        status = String(localized: "Cancelled")
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
