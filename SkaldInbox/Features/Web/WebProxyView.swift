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

    /// Whether the loopback TCP listener is currently up. Decoupled from
    /// `state == .ready` so we can tear the listener down when the app is
    /// suspended (relay goes away) while keeping the WKWebView alive with its
    /// cached content: `state` stays `.ready`, so the view never drops the
    /// webview from the hierarchy, and the next foreground silently restarts
    /// the listener on the same port.
    private var listenerActive = false

    /// Guards `sync()` against overlapping start attempts — it is async and can
    /// be re-entered from `.task` / `.onChange` in quick succession.
    private var listenerStarting = false

    /// The URL we last handed to the WebView, or `nil` if the webview is not
    /// currently mounted in the hierarchy. Memoised so that, on a silent
    /// listener restart, we can reuse the exact same `URL` object when the port
    /// is stable (preferred 50001): keeping `state` unchanged means the
    /// `WebView` is not rebuilt and does not reload its content. Reset to
    /// `nil` whenever a state transition would drop the webview (`.failed`,
    /// `.notConnected`, full `stop()`).
    private var lastReadyURL: URL?

    /// Reconcile the proxy with the connection state. Safe to call repeatedly
    /// (on appear, on every phase change, and when activation flips).
    ///
    /// The key invariant for background → foreground resilience: once the
    /// WebView has loaded once (`lastReadyURL != nil`), the relay dropping
    /// does NOT change `state` away from `.ready` — only the TCP listener is
    /// stopped. The webview therefore stays mounted with its cached content,
    /// and on reconnect the listener is restarted *silently* (without flashing
    /// a `ProgressView`, which would destroy the webview) reusing the same URL
    /// when the port is unchanged.
    ///
    /// - Parameters:
    ///   - connected: Whether the relay session is currently authenticated.
    ///   - active: Whether a web-backed tab is currently visible.
    func sync(session: SkaldSession, connected: Bool, active: Bool) async {
        guard connected else {
            // Relay down. If the webview has already loaded once, keep it alive
            // with its cached content: stop only the TCP listener and leave
            // `state` as `.ready` so the view never drops the WKWebView.
            if lastReadyURL != nil {
                server?.stop()
                server = nil
                listenerActive = false
                return
            }
            // Never been ready yet → show the not-connected placeholder.
            stop()
            state = .notConnected
            return
        }
        if active { everActivated = true }
        // Don't spin up the proxy until the user first enters Projects/Chat.
        guard everActivated else { return }

        // Listener already up, or a start is in flight → nothing to do.
        if listenerActive || listenerStarting { return }

        // A "silent" restart keeps the existing WKWebView mounted (no
        // `.starting` → ProgressView flash that would destroy it). We only do
        // this once the webview has loaded at least once.
        let silentRestart = lastReadyURL != nil
        if !silentRestart {
            state = .starting
        }
        listenerStarting = true
        defer { listenerStarting = false }

        let server = LocalHTTPProxyServer(session: session)
        self.server = server
        do {
            let port = try await server.start()
            // Load mobile.html directly: index.html's mobile redirect uses an
            // absolute path and would strip the `?native=true` query (and the
            // hash) — this also saves a round-trip.
            guard let url = URL(string: "http://127.0.0.1:\(port)/mobile.html") else {
                self.server = nil
                self.lastReadyURL = nil
                state = .failed("URL non valida")
                return
            }
            listenerActive = true
            // Reuse the memoised URL when the port is unchanged so `state`
            // stays `.ready(lastReadyURL)` — no value change → no view rebuild,
            // no reload. If the port drifted (rare race on restart) or we are
            // recovering from a non-`.ready` state, update the URL.
            if silentRestart, url == lastReadyURL, case .ready = state {
                return
            }
            lastReadyURL = url
            state = .ready(url)
        } catch {
            self.server = nil
            self.lastReadyURL = nil
            state = .failed(error.localizedDescription)
        }
    }

    func stop() {
        server?.stop()
        server = nil
        listenerActive = false
        listenerStarting = false
        lastReadyURL = nil
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
