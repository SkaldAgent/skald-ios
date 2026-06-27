//
//  SkaldSession+Pipe.swift
//  Skald
//
//  Pipe control plane: signaling, waiter bookkeeping, open/accept/reject.
//  Integrated into SkaldSession as an extension.
//
//  See docs/relay/pipe.md §2 and §6 for normative reference.
//

import CryptoKit
import Foundation
import os
import Security

extension SkaldSession {

    // MARK: - Public API (pipe control plane)

    /// Open an E2E-encrypted byte pipe to the agent (initiator role).
    /// Brokers the `pipe_invite` over the E2E channel, waits for `pipe_accept`,
    /// derives the per-pipe key, then dials the data plane.
    ///
    /// The invite is sent on the live channel (`live=true`). If the agent is
    /// offline the relay sends `PeerOffline` and this method throws after the
    /// 30s timeout.
    func openPipe(streamType: String, headers: [String: String] = [:]) async throws -> PipeConnection {
        guard let identity, let engine, let transport else {
            throw SkaldError.relayError("not connected")
        }

        // 1. Generate ephemeral X25519 keypair
        let ephPriv = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = ephPriv.publicKey.rawRepresentation  // 32B

        // 2. Generate single-use connection_id
        let cid = try Self.generateConnectionId()

        // 3. Build and send pipe_invite
        let invite = PipeInvite(
            connectionId: cid,
            suite: .x25519Sealed,
            handshake: ephPub,
            streamType: streamType,
            compress: [.none],
            headers: headers
        )
        try await sendPipeSignal(.invite(invite), to: identity.agentEd25519Pub, engine: engine, via: transport)

        // 4. Wait for accept/reject (with timeout)
        let accept = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<PipeAccept, any Error>) in
            let timeoutTask = Task { [weak self] in
                do { try await Task.sleep(nanoseconds: Self.pipeAcceptTimeout) } catch { return }
                await self?.handlePipeTimeout(cid: cid)
            }
            pipeWaiters[cid] = PipeWaiterEntry(continuation: cont, timeoutTask: timeoutTask)
        }

        // 5. Derive per-pipe key
        let peerEphPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: accept.handshake)
        let sharedSecret = try ephPriv.sharedSecretFromKeyAgreement(with: peerEphPub)
        let pipeKey = PipeCrypto.derivePipeKey(sharedSecret: sharedSecret)

        // 6. Dial the data plane
        return try await PipeConnection.connect(
            relayUrl: identity.relayURL,
            signingKey: identity.keypair.signing,
            myEdPub: identity.myEd25519Pub,
            peerEdPub: identity.agentEd25519Pub,
            namespaceIdRaw: identity.namespaceIdRaw,
            connectionId: cid,
            pipeKey: pipeKey,
            role: .initiator
        )
    }

    /// Subscribe to inbound pipe invites (responder role).
    /// Each invite must be accepted or rejected exactly once.
    func incomingPipes() -> AsyncStream<IncomingPipe> {
        var cont: AsyncStream<IncomingPipe>.Continuation!
        let stream = AsyncStream<IncomingPipe> { cont = $0 }
        let id = UUID()
        incomingPipeConsumers[id] = cont
        cont.onTermination = { [weak self] _ in
            Task { await self?.removeIncomingPipeConsumer(id) }
        }
        return stream
    }

    /// Accept an inbound invite → returns the live data-plane channel.
    func acceptPipe(_ incoming: IncomingPipe) async throws -> PipeConnection {
        guard let identity, let engine, let transport else {
            throw SkaldError.relayError("not connected")
        }

        // 1. Validate suite (v1: only X25519Sealed)
        guard incoming.suite == .x25519Sealed else {
            throw SkaldError.relayError("unsupported pipe suite")
        }

        // 2. Parse peer's ephemeral pubkey
        let peerEphPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: incoming.peerHandshake)

        // 3. Generate our ephemeral keypair
        let ephPriv = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = ephPriv.publicKey.rawRepresentation

        // 4. Derive per-pipe key
        let sharedSecret = try ephPriv.sharedSecretFromKeyAgreement(with: peerEphPub)
        let pipeKey = PipeCrypto.derivePipeKey(sharedSecret: sharedSecret)

        // 5. Send pipe_accept (E2E, live=true)
        let accept = PipeAccept(
            connectionId: incoming.connectionId,
            suite: .x25519Sealed,
            handshake: ephPub,
            compress: .none
        )
        try await sendPipeSignal(.accept(accept), to: incoming.from, engine: engine, via: transport)

        // 6. Dial the data plane
        return try await PipeConnection.connect(
            relayUrl: identity.relayURL,
            signingKey: identity.keypair.signing,
            myEdPub: identity.myEd25519Pub,
            peerEdPub: incoming.from,
            namespaceIdRaw: identity.namespaceIdRaw,
            connectionId: incoming.connectionId,
            pipeKey: pipeKey,
            role: .responder
        )
    }

    /// Decline an inbound invite.
    func rejectPipe(_ incoming: IncomingPipe, reason: String) async throws {
        guard let engine, let transport else {
            throw SkaldError.relayError("not connected")
        }
        let reject = PipeReject(connectionId: incoming.connectionId, reason: reason)
        try await sendPipeSignal(.reject(reject), to: incoming.from, engine: engine, via: transport)
    }

    // MARK: - Internal: pipe signal routing

    /// Called from `handleIncoming` when a decrypted plaintext has framing
    /// version `0x02` (pipe signal). Dispatches to waiter or incoming consumer.
    func handlePipeSignal(from: Data, body: Data) async {
        let signal: PipeSignal
        do {
            signal = try PipeSignal.decode(from: body)
        } catch {
            let hex = body.prefix(64).map { String(format: "%02x", $0) }.joined()
            log.warning("malformed pipe signal: \(error.localizedDescription, privacy: .public) body=\(body.count, privacy: .public)B hex=\(hex, privacy: .public)")
            return
        }

        switch signal {
        case .invite(let inv):
            let incoming = IncomingPipe(
                from: from,
                streamType: inv.streamType,
                headers: inv.headers,
                connectionId: inv.connectionId,
                suite: inv.suite,
                peerHandshake: inv.handshake
            )
            for c in incomingPipeConsumers.values { c.yield(incoming) }

        case .accept(let acc):
            if let entry = removeWaiter(acc.connectionId) {
                entry.continuation.resume(returning: acc)
            }

        case .reject(let rej):
            if let entry = removeWaiter(rej.connectionId) {
                entry.continuation.resume(throwing: SkaldError.relayError(rej.reason))
            }
        }
    }

    // MARK: - Internal: send pipe signal

    /// Send a pipe-signaling message sealed for the E2E channel.
    /// The framing (version=0x02) is pre-appended; `sealFramed` encrypts
    /// without adding its own framing.
    private func sendPipeSignal(
        _ signal: PipeSignal,
        to peer: Data,
        engine: CryptoEngine,
        via transport: RelayClient
    ) async throws {
        let msgpack = signal.encode()
        let framed = PipeCrypto.framePipeSignal(msgpack)

        let nextCounter = try KeychainStore.shared.incrementCounter(for: KeychainStore.Key.sendCounter)
        let (nonce, sealed) = try engine.sealFramed(
            plaintext: framed,
            direction: CryptoConstants.nonceDirClientToAgent,
            counterSource: { nextCounter }
        )
        try await transport.sendEnvelope(
            ciphertext: sealed, nonce: nonce, peer: peer, live: true
        )
    }

    // MARK: - Internal: waiter bookkeeping

    /// Remove and return the waiter for `connectionId`, cancelling its timeout task.
    private func removeWaiter(_ connectionId: Data) -> PipeWaiterEntry? {
        guard let entry = pipeWaiters.removeValue(forKey: connectionId) else { return nil }
        entry.timeoutTask.cancel()
        return entry
    }

    /// Called by the timeout task when the accept window expires.
    func handlePipeTimeout(cid: Data) {
        guard let entry = pipeWaiters.removeValue(forKey: cid) else { return }
        entry.continuation.resume(throwing: SkaldError.relayError("pipe accept timeout"))
    }

    /// Resolve all pending pipe waiters with a "disconnected" error.
    func cancelAllPipeWaiters() {
        for (_, entry) in pipeWaiters {
            entry.timeoutTask.cancel()
            entry.continuation.resume(throwing: SkaldError.relayError("disconnected"))
        }
        pipeWaiters.removeAll()
    }

    // MARK: - Helpers

    private func removeIncomingPipeConsumer(_ id: UUID) {
        incomingPipeConsumers[id] = nil
    }

    /// Generate 32 random bytes for a single-use connection_id.
    private static func generateConnectionId() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        guard status == errSecSuccess else {
            throw SkaldError.keychainError(status)
        }
        return Data(bytes)
    }
}
