//
//  SkaldApp.swift
//  Skald
//
//  App entry point. Hosts the SwiftUI scene, the AppDelegate adaptor, the
//  single `AppState` instance, and the `RootView` that switches between
//  Scan / Pairing / Inbox flows based on the pairing phase.
//

import SwiftUI
import UserNotifications

@main
struct SkaldApp: App {

    /// Hooks for push registration and notification action handling.
    @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate

    /// Single source of truth for the whole app.
    @StateObject private var appState = AppState()

    /// Track scene phase so we can react to background → foreground.
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(appState)
                .onAppear {
                    // Make sure the AppDelegate has a reference to appState
                    // (it needs it for the willPresent / didReceive callbacks
                    // and to store the APNs device token).
                    delegate.appState = appState
                }
                .onChange(of: scenePhase) { _, newPhase in
                    if newPhase == .active {
                        // Re-deliver the appState pointer in case the scene
                        // was rebuilt (e.g. after a memory warning).
                        delegate.appState = appState
                    }
                }
        }
    }
}

// MARK: - AppState

/// App-wide observable state. Owns the pairing phase machine, the APNs
/// device token (hex), and the locally-derived identity (my Ed25519 / X25519
/// pubkeys read from Keychain on demand).
@MainActor
final class AppState: ObservableObject {

    // MARK: - Phases

    enum Phase: Equatable {
        case notPaired
        case pairing(PairingQRData)
        case awaitingAuth(PairingQRData)
        case connected
        case disconnected
    }

    // MARK: - Published state

    @Published private(set) var phase: Phase

    /// Hex-encoded APNs device token. Loaded from Keychain at launch and
    /// refreshed by `AppDelegate` once `didRegister` fires. Read by
    /// `RelayClient` during auth so the agent can route push notifications to
    /// this device.
    @Published var deviceTokenHex: String?

    /// Invoked by `AppDelegate` when the APNs token arrives or rotates after
    /// the relay session is already up. The `InboxViewModel` wires this to a
    /// reconnect so the relay learns the fresh token.
    var onDeviceTokenChanged: (() -> Void)?

    /// The QR data that was last successfully scanned.  Kept on the state so
    /// `.awaitingAuth` can show the PairingView with the right metadata.
    private(set) var lastPairingQR: PairingQRData?

    /// The single, app-wide E2E client.  Owns the one long-lived relay
    /// connection; every feature view-model subscribes to it.
    let session: SkaldSession

    // MARK: - Init

    init() {
        // Derive the initial phase from Keychain: if we have a stored seed,
        // namespace id, and relay URL, we're previously-paired — start in
        // `.disconnected` so the inbox view-model reconnects.
        let hasSeed  = (try? KeychainStore.shared.getData(for: KeychainStore.Key.seed)) != nil
        let hasNS    = (try? KeychainStore.shared.getData(for: KeychainStore.Key.namespaceId)) != nil
        let hasRelay = (try? KeychainStore.shared.getString(for: KeychainStore.Key.relayUrl)) != nil
        if hasSeed, hasNS, hasRelay {
            self.phase = .disconnected
        } else {
            self.phase = .notPaired
        }
        // Restore the last-known APNs token so the first relay connect after a
        // cold launch sends it immediately, instead of an empty placeholder.
        self.deviceTokenHex = (try? KeychainStore.shared.getString(for: KeychainStore.Key.deviceToken)) ?? nil

        let session = SkaldSession()
        self.session = session
        // When the APNs token arrives/rotates after we're already connected,
        // force a fresh session so the relay re-learns the token.
        self.onDeviceTokenChanged = { Task { await session.reconnect() } }
    }

    // MARK: - Phase transitions (called by the feature view-models)

    /// Begin pairing with a freshly-scanned QR.
    func startPairing(qrData: PairingQRData) {
        lastPairingQR = qrData
        phase = .pairing(qrData)
    }

    /// Pairing WS closed cleanly — credentials persisted, agent is being
    /// told about the new device.  Transition to `.awaitingAuth`.
    func didCompletePairing(qrData: PairingQRData) {
        lastPairingQR = qrData
        phase = .awaitingAuth(qrData)
    }

    /// The first `.client` session successfully authenticated.
    func handleAuthOk() {
        phase = .connected
    }

    /// The `.client` session reported a relay error.  If it's an auth error
    /// (`.relayError("…unauthorized…")`), we go back to `.notPaired`; otherwise
    /// `.disconnected` and the InboxViewModel keeps retrying.
    func handleAuthError(_ error: SkaldError) {
        if case .relayError(let msg) = error, msg.contains("unauthorized") {
            phase = .notPaired
            lastPairingQR = nil
        } else {
            phase = .disconnected
        }
    }

    /// The InboxViewModel's session went down.  Move to `.disconnected`.
    func handleDisconnected() {
        if case .notPaired = phase { return }
        phase = .disconnected
    }

    /// Cancel the current pairing attempt and return to the scan screen.
    /// Used when the user taps "Cancel" in the awaiting-confirm state.
    func cancelPairing() {
        lastPairingQR = nil
        phase = .notPaired
    }

    /// Logout completed.  Wipe everything and go back to `.notPaired`.
    func didLogout() {
        lastPairingQR = nil
        deviceTokenHex = nil
        try? KeychainStore.shared.delete(for: KeychainStore.Key.deviceToken)
        phase = .notPaired
    }

    // MARK: - Identity helpers (read from Keychain on demand)

    /// Our Ed25519 public key (raw 32B).  Returns `nil` if we're not paired.
    var myEd25519Pub: Data? {
        return Self.readKeychainData(KeychainStore.Key.myEd25519Pub)
    }

    /// Our X25519 public key (raw 32B).
    var myX25519Pub: Data? {
        return Self.readKeychainData(KeychainStore.Key.myX25519Pub)
    }

    /// Hex-encoded our pubkeys — convenient for `RelayClient` init.
    var myEd25519PubHex: String? { myEd25519Pub.map { Hex.encode($0) } }
    var myX25519PubHex: String?  { myX25519Pub.map  { Hex.encode($0) } }

    /// Hex of the stored namespace id (computed during pairing).
    var namespaceIdHex: String? {
        Self.readKeychainData(KeychainStore.Key.namespaceId).map { Hex.encode($0) }
    }

    /// Read a 32-byte Data entry from Keychain.  Returns `nil` on missing
    /// entry, keychain error, or wrong size.  Used for the identity helpers.
    private static func readKeychainData(_ account: String) -> Data? {
        guard let data = try? KeychainStore.shared.getData(for: account),
              data.count == 32
        else { return nil }
        return data
    }
}

// MARK: - RootView

/// Switches the root content based on the pairing phase.  Each phase has its
/// own NavigationStack / TabView so navigation state is preserved when the
/// phase changes (only the previously-active stack is discarded).
struct RootView: View {

    @EnvironmentObject private var appState: AppState

    var body: some View {
        switch appState.phase {
        case .notPaired:
            NavigationStack {
                ScanView { qr in
                    appState.startPairing(qrData: qr)
                }
            }

        case .pairing(let qr):
            NavigationStack {
                PairingView(qrData: qr, awaiting: false)
            }

        case .awaitingAuth(let qr):
            NavigationStack {
                PairingView(qrData: qr, awaiting: true)
            }

        case .connected, .disconnected:
            MainTabView()
        }
    }
}

// MARK: - MainTabView

/// The "I'm paired" root — Inbox + Settings.  Both tabs share the same
/// `InboxViewModel` so the WS session survives tab switches.
struct MainTabView: View {

    @EnvironmentObject private var appState: AppState
    @StateObject private var inboxVM = InboxViewModel()

    /// React to background → foreground so we re-open the WS session if it
    /// went down while suspended.
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        TabView {
            NavigationStack {
                InboxView()
                    .environmentObject(inboxVM)
            }
            .tabItem {
                Label("Inbox", systemImage: "tray.full")
            }

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
        }
        .environmentObject(inboxVM)
        .task {
            // Hook the view-model up to appState. We do it in `.task` (idempotent)
            // so the binding survives view rebuilds.
            inboxVM.attach(appState: appState)
            inboxVM.connect()
        }
        .onChange(of: scenePhase) { _, newPhase in
            switch newPhase {
            case .active:
                // Coming back to the foreground: re-open the WS so we resume
                // streaming events. `connect()` is idempotent — a no-op when
                // already connected/connecting.
                inboxVM.connect()
            case .background:
                // Going to the background: tear the WS down. We don't need a
                // live stream while suspended — APNs pushes cover that — and
                // keeping the session (+ 25s keepalive + reconnect-with-backoff
                // loop) alive only accumulates memory/battery until iOS
                // suspends us, which is what got the app jetsam-killed.
                inboxVM.disconnect()
            case .inactive:
                // Transient (app switcher, notification center, incoming call).
                // Don't churn the connection — wait for .background or .active.
                break
            @unknown default:
                break
            }
        }
    }
}
