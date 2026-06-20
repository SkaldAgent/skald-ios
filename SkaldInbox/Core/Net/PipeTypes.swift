//
//  PipeTypes.swift
//  Skald
//
//  Struct/enum for all pipe protocol message types.
//  See docs/relay/pipe.md for normative reference.
//

import Foundation

// MARK: - Suite & compression

/// Handshake suite discriminator (pipe.md §2).
/// v1 only supports `.x25519Sealed`.
enum PipeSuite: String, Equatable {
    case x25519Sealed = "x25519-sealed"
}

/// Per-direction compression codec (pipe.md §5).
enum PipeCompress: String, Equatable {
    case none = "none"
    case zlib = "zlib"
}

// MARK: - Control plane (E2E signaling)

struct PipeInvite: Equatable {
    let connectionId: Data       // 32B
    let suite: PipeSuite
    let handshake: Data          // 32B ephemeral X25519 pub
    let streamType: String
    let compress: [PipeCompress]
    let headers: [String: String]
}

struct PipeAccept: Equatable {
    let connectionId: Data       // 32B
    let suite: PipeSuite
    let handshake: Data          // 32B ephemeral X25519 pub
    let compress: PipeCompress
}

struct PipeReject: Equatable {
    let connectionId: Data       // 32B
    let reason: String
}

/// Externally tagged: `{"Invite":{...}}` / `{"Accept":{...}}` / `{"Reject":{...}}`
enum PipeSignal: Equatable {
    case invite(PipeInvite)
    case accept(PipeAccept)
    case reject(PipeReject)
}

// MARK: - Data plane (on /v1/pipe)

struct PipeChallenge: Equatable {
    let nonce: Data              // 32B
}

struct PipeAuth: Equatable {
    let connectionId: Data       // 32B
    let pubkey: Data             // 32B ed25519
    let dest: Data               // 32B SHA256(peer_ed_pub)
    let namespaceId: Data        // 32B raw
    let signature: Data          // 64B ed25519
}

// MARK: - Surface type

/// Surfaced to the app when a pipe invite arrives.
struct IncomingPipe: Equatable, Sendable {
    let from: Data               // 32B initiator ed25519 pubkey
    let streamType: String
    let headers: [String: String]
    // Internal — not exposed to consumer, used by accept/reject:
    let connectionId: Data
    let suite: PipeSuite
    let peerHandshake: Data
}
