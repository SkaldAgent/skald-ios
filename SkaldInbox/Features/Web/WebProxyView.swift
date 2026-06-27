//
//  WebProxyView.swift
//  Skald
//
//  The single web-backed surface shared by the Projects and Chat tabs. It owns
//  no WKWebView of its own (that lives in `WebView`); instead it manages the
//  loopback proxy lifecycle and, once the proxy is ready, mounts the shared
//  `WebView` pointed at it. Because the same view instance is kept alive across
//  Projects ↔ Chat switches, the underlying WKWebView (and its in-page state)
//  persists — which is what lets "tap a project → jump to its chat" happen
//  inside one continuous page.
//

import SwiftUI

// MARK: - ViewModel

@MainActor
final class WebProxyViewModel: ObservableObject {

    enum State: Equatable {
        case idle
        case starting
        case ready(URL)
        case notConnected
        case failed(String)
    }

    @Published private(set) var state: State = .idle

    private var server: LocalHTTPProxyServer?

    /// Set to true the first time the web surface is actually shown. The proxy
    /// is kept alive from then on (so switching away and back is instant), but
    /// we don't open relay pipes on launch if the user never opens Projects/Chat.
    private var everActivated = false

    /// Reconcile the proxy with the connection state. Safe to call repeatedly
    /// (on appear, on every phase change, and when activation flips).
    ///
    /// - Parameters:
    ///   - connected: Whether the relay session is currently authenticated.
    ///   - active: Whether a web-backed tab is currently visible.
    func sync(session: SkaldSession, connected: Bool, active: Bool) async {
        guard connected else {
            stop()
            state = .notConnected
            return
        }
        if active { everActivated = true }
        // Don't spin up the proxy until the user first enters Projects/Chat.
        guard everActivated else { return }

        // Already serving or mid-start → nothing to do.
        if case .ready = state { return }
        if case .starting = state { return }

        state = .starting
        let server = LocalHTTPProxyServer(session: session)
        self.server = server
        do {
            let port = try await server.start()
            // Load mobile.html directly: index.html's mobile redirect uses an
            // absolute path and would strip the `?native=true` query (and the
            // hash) — this also saves a round-trip.
            guard let url = URL(string: "http://127.0.0.1:\(port)/mobile.html") else {
                self.server = nil
                state = .failed("URL non valida")
                return
            }
            state = .ready(url)
        } catch {
            self.server = nil
            state = .failed(error.localizedDescription)
        }
    }

    func stop() {
        server?.stop()
        server = nil
        switch state {
        case .ready, .starting:
            state = .idle
        default:
            break
        }
    }
}

// MARK: - View

struct WebProxyView: View {

    @EnvironmentObject private var appState: AppState
    @ObservedObject var vm: WebProxyViewModel

    /// The section the native side currently wants shown.
    let section: WebSection

    /// Document the file viewer should show (only while the Doc tab is active).
    let filePath: String?

    /// Whether a web-backed tab is currently visible (gates proxy start).
    let active: Bool

    /// Forwarded from the underlying webview when the SPA navigates on its own
    /// (carrying the document path for the file-viewer section).
    var onSectionChange: (WebSection, String?) -> Void

    private var connected: Bool { appState.phase == .connected }

    var body: some View {
        content
            .task { await vm.sync(session: appState.session, connected: connected, active: active) }
            .onChange(of: connected) { _, isConnected in
                Task { await vm.sync(session: appState.session, connected: isConnected, active: active) }
            }
            .onChange(of: active) { _, isActive in
                Task { await vm.sync(session: appState.session, connected: connected, active: isActive) }
            }
    }

    @ViewBuilder
    private var content: some View {
        switch vm.state {
        case .idle, .starting:
            ProgressView("Avvio proxy locale…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)

        case .ready(let url):
            WebView(baseURL: url, section: section, filePath: filePath, onSectionChange: onSectionChange)
                .ignoresSafeArea(.container, edges: .top)

        case .notConnected:
            ContentUnavailableView(
                "Agent non connesso",
                systemImage: "wifi.slash",
                description: Text("La WebView si attiva quando la sessione con l'agent è connessa.")
            )

        case .failed(let message):
            ContentUnavailableView {
                Label("Proxy non avviato", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            } actions: {
                Button("Riprova") {
                    Task { await vm.sync(session: appState.session, connected: connected, active: active) }
                }
            }
        }
    }
}
