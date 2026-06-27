//
//  WebView.swift
//  Skald
//
//  SwiftUI wrapper around a single, persistent WKWebView that displays the
//  agent's HTTP UI (served through the local proxy). Drives the web SPA's
//  section via the URL hash and listens for the SPA's `skaldNav` messages so
//  the native tab bar can follow client-side navigation.
//
//  Navigation contract with the web SPA (~/projects/skald/web/mobile.html):
//    • native presence is signalled with the `?native=true` query parameter
//      (the web side hides its own bottom nav when this is set);
//    • the section is carried in the URL fragment (no leading slash):
//          #projects                →  projects page
//          #chat                    →  chat page (main session)
//          #chat/project-…          →  chat page bound to a project's session
//          #file_viewer?path=<enc>  →  file viewer showing a document
//    • the web SPA reports every section change to the native shell via
//      `window.webkit.messageHandlers.skaldNav.postMessage({section, project, path})`,
//      which this wrapper listens on so the native tab bar can follow it (the
//      `path` is only present for the `file_viewer` section).
//
//  Links pointing outside the loopback proxy (any other host, plus non-web
//  schemes like mailto:/tel:) are handed off to the system browser instead of
//  loading inside the embedded webview — see the WKNavigationDelegate below.
//

import SwiftUI
import WebKit
import UIKit

// MARK: - WebSection

/// The web-backed sections the native app exposes as top-level tabs.
enum WebSection: String {
    case projects
    case chat
    case fileViewer = "file_viewer"

    /// URL fragment used to drive the web SPA, including the leading `#`.
    /// Matches the web router's hash format (`mobile-app.js` `_readHash`):
    /// `#projects`, `#chat`, `#file_viewer` (no leading slash).
    var hash: String { "#\(rawValue)" }
}

// MARK: - WebView

struct WebView: UIViewRepresentable {

    /// Proxy base URL, e.g. `http://127.0.0.1:<port>/`.
    let baseURL: URL

    /// The section the native side currently wants the web SPA to show.
    let section: WebSection

    /// File the `fileViewer` section should display (the "last opened document").
    /// Ignored for every other section.
    var filePath: String?

    /// Invoked whenever the web SPA navigates to a different section on its own
    /// (e.g. the user taps a project, moving from #projects to #chat, or opens a
    /// file from the chat → `.fileViewer` with the document's path).
    var onSectionChange: (WebSection, String?) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onSectionChange: onSectionChange)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()

        // Register the `skaldNav` message handler so the web SPA can report
        // section changes (mobile-app.js `_notifyNative` posts
        // `{section, project, path}`). The web side is the single source of truth
        // for routing — it already reacts to hashchange/popstate itself — so we
        // don't inject any observer here.
        let cc = WKUserContentController()
        cc.add(context.coordinator, name: Coordinator.messageName)
        config.userContentController = cc

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.allowsBackForwardNavigationGestures = true
        // Route external links / non-web schemes to Safari (see delegate methods).
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        context.coordinator.webView = webView
        context.coordinator.baseURL = baseURL
        context.coordinator.lastSection = section
        context.coordinator.lastFilePath = filePath

        webView.load(URLRequest(url: Self.url(base: baseURL, section: section, filePath: filePath)))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        // Keep the callback fresh (closures captured by value on rebuild).
        context.coordinator.onSectionChange = onSectionChange

        // The proxy restarted on a new port → full reload with the new base.
        if context.coordinator.baseURL != baseURL {
            context.coordinator.baseURL = baseURL
            context.coordinator.lastSection = section
            context.coordinator.lastFilePath = filePath
            webView.load(URLRequest(url: Self.url(base: baseURL, section: section, filePath: filePath)))
            return
        }

        // The native selection moved (between sections, or — within the file
        // viewer — onto a different document) → nudge the hash. Setting
        // location.hash does NOT reload the document, so in-page state (scroll,
        // chat draft) survives.
        if context.coordinator.lastSection != section || context.coordinator.lastFilePath != filePath {
            context.coordinator.lastSection = section
            context.coordinator.lastFilePath = filePath
            let fragment = Self.fragment(section: section, filePath: filePath)
            webView.evaluateJavaScript("location.hash = '#\(fragment)';")
        }
    }

    /// Builds `<base>?native=true#<fragment>` preserving any query already
    /// present on the base URL (`base` is the mobile.html proxy URL).
    private static func url(base: URL, section: WebSection, filePath: String?) -> URL {
        var comp = URLComponents(url: base, resolvingAgainstBaseURL: false) ?? URLComponents()
        var items = comp.queryItems ?? []
        if !items.contains(where: { $0.name == "native" }) {
            items.append(URLQueryItem(name: "native", value: "true"))
        }
        comp.queryItems = items
        // The fragment is already percent-encoded (the file viewer carries an
        // encoded `?path=`), so set it verbatim rather than letting URLComponents
        // re-encode the `%` escapes.
        comp.percentEncodedFragment = fragment(section: section, filePath: filePath)
        return comp.url ?? base
    }

    /// The URL fragment (without the leading `#`) for a section. The file viewer
    /// carries the document path as a nested, percent-encoded query so the web
    /// router (`mobile-app.js` `_readHash`) can recover it: `file_viewer?path=…`.
    private static func fragment(section: WebSection, filePath: String?) -> String {
        guard section == .fileViewer, let path = filePath, !path.isEmpty else {
            return section.rawValue
        }
        let enc = path.addingPercentEncoding(withAllowedCharacters: .uriComponentAllowed) ?? path
        return "file_viewer?path=\(enc)"
    }

    // MARK: - Coordinator

    final class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate, WKUIDelegate {

        /// Message handler name the web SPA posts to (`_notifyNative`).
        static let messageName = "skaldNav"

        weak var webView: WKWebView?
        /// Last base URL we loaded, so a proxy port change triggers a reload.
        var baseURL: URL?
        /// The last section value from either side; used to suppress echoes and
        /// detect genuine changes.
        var lastSection: WebSection?
        /// The last file-viewer document path from either side. Tracked alongside
        /// the section because the file viewer keeps the same section while the
        /// path changes (file A → file B).
        var lastFilePath: String?
        var onSectionChange: (WebSection, String?) -> Void

        init(onSectionChange: @escaping (WebSection, String?) -> Void) {
            self.onSectionChange = onSectionChange
        }

        // MARK: Web → Native (skaldNav)

        func userContentController(
            _ userContentController: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            // The web SPA posts `{ section: "projects" | "chat" | "file_viewer" | …,
            // project, path }`. We only care about the web-backed sections;
            // everything else is ignored (those tabs are native).
            guard let dict = message.body as? [String: Any],
                  let section = dict["section"] as? String
            else { return }

            let detected: WebSection
            switch section {
            case "projects":    detected = .projects
            case "chat":        detected = .chat
            case "file_viewer": detected = .fileViewer
            default: return
            }

            // `path` is only meaningful for the file viewer.
            let path = (detected == .fileViewer) ? (dict["path"] as? String) : nil

            // Only forward genuine changes; this also breaks the feedback loop
            // (native drives the hash → the page echoes → detected == last →
            // ignored) so we never bounce back and forth. It also prevents the
            // native side from re-driving the hash (e.g. to #chat) and
            // clobbering a #chat/project-<id> route the user just opened.
            guard detected != lastSection || path != lastFilePath else { return }
            lastSection  = detected
            lastFilePath = path
            onSectionChange(detected, path)
        }

        // MARK: External links → system browser

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let url = navigationAction.request.url,
                  let scheme = url.scheme?.lowercased()
            else { decisionHandler(.allow); return }

            if scheme == "http" || scheme == "https" {
                // A user-tapped link to a host other than the loopback proxy is an
                // external page → open it in Safari, not inside the embedded UI.
                let proxyHost = baseURL?.host ?? "127.0.0.1"
                if url.host != proxyHost, navigationAction.navigationType == .linkActivated {
                    UIApplication.shared.open(url)
                    decisionHandler(.cancel)
                    return
                }
            } else if scheme != "about" && scheme != "data" && scheme != "blob" {
                // mailto:, tel:, sms:, maps:, … → hand off to the system.
                UIApplication.shared.open(url)
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }

        func webView(
            _ webView: WKWebView,
            createWebViewWith configuration: WKWebViewConfiguration,
            for navigationAction: WKNavigationAction,
            windowFeatures: WKWindowFeatures
        ) -> WKWebView? {
            // Links with `target="_blank"` have no target frame and would
            // otherwise be silently dropped by WKWebView. Keep internal ones in
            // the existing webview; hand external ones (and non-web schemes) to
            // the system.
            if let url = navigationAction.request.url {
                let proxyHost = baseURL?.host ?? "127.0.0.1"
                let isHTTP = url.scheme == "http" || url.scheme == "https"
                if isHTTP, url.host == proxyHost {
                    webView.load(navigationAction.request)
                } else {
                    UIApplication.shared.open(url)
                }
            }
            return nil
        }

        // MARK: Media capture (microphone, camera)

        func webView(
            _ webView: WKWebView,
            requestMediaCapturePermissionFor origin: WKSecurityOrigin,
            initiatedByFrame frame: WKFrameInfo,
            type: WKMediaCaptureType,
            decisionHandler: @escaping (WKPermissionDecision) -> Void
        ) {
            decisionHandler(.grant)
        }
    }
}

// MARK: - Percent-encoding

private extension CharacterSet {
    /// Mirrors JavaScript's `encodeURIComponent` unreserved set so the encoded
    /// `path` round-trips through the web router's `decodeURIComponent`.
    static let uriComponentAllowed = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
    )
}
