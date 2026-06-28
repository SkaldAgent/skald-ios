//
//  LocalHTTPProxyServer.swift
//  Skald
//
//  PoC: a loopback TCP listener that tunnels each inbound connection through an
//  E2E relay pipe (stream_type = "http-local-proxy"). The Web tab points a
//  WKWebView at this listener so the agent's local HTTP server is reachable
//  without any plaintext traffic ever leaving the device.
//
//  WKWebView runs out-of-process and can't be intercepted via URLProtocol, so a
//  real TCP listener is the only way to capture its http:// traffic. Each TCP
//  connection is mapped 1:1 to a transparent byte pipe — no HTTP parsing here;
//  the agent side runs the actual HTTP server.
//
//  Port selection: prefers a stable high port (50 001) so WKWebView can reuse its
//  HTTP cache across app launches. If that port is taken, falls back to an
//  OS-assigned ephemeral port (port 0).
//

import Foundation
import Network
import os

/// Loopback TCP → relay-pipe proxy. One TCP connection ↔ one pipe.
final class LocalHTTPProxyServer {

    /// The pipe stream_type the agent's mobile connector listens for.
    static let streamType = "http-local-proxy"

    /// Preferred stable port — keeps WKWebView cache alive across launches.
    /// Change this if 50001 clashes with another service on your machine.
    static let preferredPort: UInt16 = 50_001

    private let session: SkaldSession
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "net.skaldagent.inbox.proxy")
    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "LocalHTTPProxyServer")

    init(session: SkaldSession) {
        self.session = session
    }

    // MARK: - Lifecycle

    /// Start listening on loopback. Tries `preferredPort` first for WebView cache
    /// stability; falls back to an OS-assigned ephemeral port if the preferred
    /// port is already in use. Returns the bound port.
    func start() async throws -> UInt16 {
        do {
            return try await startOnPort(Self.preferredPort)
        } catch {
            log.warning("preferred port \(Self.preferredPort, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
        return try await startOnPort(0)
    }

    /// Start listening on a specific port (or 0 for OS-assigned).
    /// Returns the bound port once the listener is `.ready`.
    private func startOnPort(_ port: UInt16) async throws -> UInt16 {
        let params = NWParameters.tcp
        // Pin the listener to loopback so nothing else on the network can reach it.
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        params.allowLocalEndpointReuse = true

        let listener: NWListener
        if port == 0 {
            listener = try NWListener(using: params)
        } else {
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                throw SkaldError.networkError("proxy: invalid port \(port)")
            }
            listener = try NWListener(using: params, on: nwPort)
        }
        self.listener = listener

        listener.newConnectionHandler = { [weak self] conn in
            self?.handle(conn)
        }

        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<UInt16, any Error>) in
            var resumed = false
            listener.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    guard !resumed else { return }
                    resumed = true
                    let boundPort = listener.port?.rawValue ?? 0
                    self?.log.info("proxy listening on 127.0.0.1:\(boundPort, privacy: .public)")
                    cont.resume(returning: boundPort)
                case .failed(let error):
                    guard !resumed else { return }
                    resumed = true
                    cont.resume(throwing: error)
                case .cancelled:
                    guard !resumed else { return }
                    resumed = true
                    cont.resume(throwing: SkaldError.networkError("proxy listener cancelled"))
                default:
                    break
                }
            }
            listener.start(queue: queue)
        }
    }

    /// Stop the listener. In-flight tunnels finish on their own when their TCP
    /// connection or pipe closes.
    func stop() {
        listener?.cancel()
        listener = nil
    }

    // MARK: - Per-connection tunnel

    private func handle(_ conn: NWConnection) {
        let connId = UInt16.random(in: 0...UInt16.max)
        log.notice("conn[\(connId, privacy: .public)] tcp accepted")
        conn.start(queue: queue)
        Task { [session, log] in
            await Self.runTunnel(connId: connId, conn: conn, session: session, log: log)
        }
    }

    private static func runTunnel(connId: UInt16, conn: NWConnection, session: SkaldSession, log: Logger) async {
        let pipe: PipeConnection
        do {
            pipe = try await session.openPipe(streamType: streamType)
        } catch {
            log.error("conn[\(connId, privacy: .public)] openPipe failed: \(error.localizedDescription, privacy: .public)")
            conn.cancel()
            return
        }
        log.notice("conn[\(connId, privacy: .public)] pipe open")

        // Pump both directions; when either side ends, tear the whole thing down
        // so the other pump unblocks.
        await withTaskGroup(of: String.self) { group in
            group.addTask { await pumpTCPToPipe(connId: connId, conn: conn, pipe: pipe, log: log) }
            group.addTask { await pumpPipeToTCP(connId: connId, conn: conn, pipe: pipe, log: log) }
            let first = await group.next() ?? "?"
            log.notice("conn[\(connId, privacy: .public)] tearing down (first ended: \(first, privacy: .public))")
            await pipe.close()
            conn.cancel()
            group.cancelAll()
        }
    }

    /// TCP → pipe: read bytes from the browser, seal+send over the pipe.
    /// Returns a short reason describing why it ended (for logging).
    private static func pumpTCPToPipe(connId: UInt16, conn: NWConnection, pipe: PipeConnection, log: Logger) async -> String {
        var total = 0
        while true {
            let chunk: Data?
            do {
                chunk = try await tcpReceive(conn)
            } catch {
                log.notice("conn[\(connId, privacy: .public)] tcp→pipe end: tcp recv error after \(total, privacy: .public)B: \(error.localizedDescription, privacy: .public)")
                return "tcp recv error"
            }
            guard let data = chunk, !data.isEmpty else {
                log.notice("conn[\(connId, privacy: .public)] tcp→pipe end: tcp EOF after \(total, privacy: .public)B")
                return "tcp EOF"
            }
            do {
                try await pipe.send(data)
            } catch {
                log.notice("conn[\(connId, privacy: .public)] tcp→pipe end: pipe send error after \(total, privacy: .public)B: \(error.localizedDescription, privacy: .public)")
                return "pipe send error"
            }
            total += data.count
            log.notice("conn[\(connId, privacy: .public)] tcp→pipe \(data.count, privacy: .public)B (total \(total, privacy: .public)B)")
        }
    }

    /// pipe → TCP: read bytes from the pipe, write to the browser.
    /// Returns a short reason describing why it ended (for logging).
    private static func pumpPipeToTCP(connId: UInt16, conn: NWConnection, pipe: PipeConnection, log: Logger) async -> String {
        var total = 0
        while true {
            let chunk: Data?
            do {
                chunk = try await pipe.recv()
            } catch {
                log.notice("conn[\(connId, privacy: .public)] pipe→tcp end: pipe recv error after \(total, privacy: .public)B: \(error.localizedDescription, privacy: .public)")
                return "pipe recv error"
            }
            guard let data = chunk else {
                log.notice("conn[\(connId, privacy: .public)] pipe→tcp end: pipe closed after \(total, privacy: .public)B")
                return "pipe closed"
            }
            do {
                try await tcpSend(conn, data)
            } catch {
                log.notice("conn[\(connId, privacy: .public)] pipe→tcp end: tcp send error after \(total, privacy: .public)B: \(error.localizedDescription, privacy: .public)")
                return "tcp send error"
            }
            total += data.count
            log.notice("conn[\(connId, privacy: .public)] pipe→tcp \(data.count, privacy: .public)B (total \(total, privacy: .public)B)")
        }
    }

    // MARK: - NWConnection ↔ async/await bridges

    /// Receive the next chunk. Returns `nil` on EOF.
    private static func tcpReceive(_ conn: NWConnection) async throws -> Data? {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data?, any Error>) in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let error {
                    cont.resume(throwing: error)
                    return
                }
                if let data, !data.isEmpty {
                    cont.resume(returning: data)  // deliver data; EOF surfaces on next call
                    return
                }
                cont.resume(returning: isComplete ? nil : Data())
            }
        }
    }

    private static func tcpSend(_ conn: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, any Error>) in
            conn.send(content: data, completion: .contentProcessed { error in
                if let error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume()
                }
            })
        }
    }
}
