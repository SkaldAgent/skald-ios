//
//  Payloads.swift
//  Skald
//
//  Codable structs for every E2E payload described in docs/../payloads.md.
//
//  These are the **plaintext** structures that get serialised to JSON-UTF-8
//  and then AES-256-GCM-sealed (see CryptoEngine).  The relay never sees
//  any of these; it only sees the encrypted envelope.
//
//  This file is compiled into BOTH targets (app and NSE).  The NSE only
//  needs the InboxUpdate / Notification shapes for rich-push rendering, but
//  the file is small enough that we keep everything together.
//

import Foundation

// MARK: - Common envelope

/// Fields present in every E2E payload (payloads.md §1).
struct EnvelopeBase: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
}

// MARK: - Kind enum (used as the discriminant when decoding into `Payload`)

/// The set of `kind` strings defined by the protocol.  See payloads.md §2.
enum PayloadKind: String, Codable, Equatable {
    case inboxUpdate           = "inbox_update"
    case notification          = "notification"
    case hello                 = "hello"
    case inboxRequest          = "inbox_request"
    case approvalResponse      = "approval_response"
    case clarificationResponse = "clarification_response"
    case logout                = "logout"
    case ack                   = "ack"
}

// MARK: - Agent → Client payloads

/// An item in the pending-approvals list of an `inbox_update`.
struct ApprovalItem: Codable, Equatable {
    let request_id: String
    let tool_name: String
    let agent_label: String
    let summary: String
    let detail: String?
    let created_at: Int64   // unix ms
}

/// An item in the pending-clarifications list of an `inbox_update`.
struct ClarificationItem: Codable, Equatable {
    let request_id: String
    let question: String
    let context: String?
    let agent_label: String
    let created_at: Int64   // unix ms
}

/// `kind: "inbox_update"` — agent → client, full snapshot (payloads.md §3.1).
struct InboxUpdate: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
    let badge: Int
    let approvals: [ApprovalItem]
    let clarifications: [ClarificationItem]
}

/// `kind: "notification"` — agent → client (payloads.md §3.2).
struct Notification: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
    let title: String
    let body: String
}

/// `kind: "ack"` — bidirectional (payloads.md §3.3 / §4.5).
struct Ack: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
    let ref_id: String
}

// MARK: - Client → Agent payloads

/// Free-form device metadata (payloads.md §4.1).
struct DeviceInfo: Codable, Equatable {
    let platform: String
    let model: String?
    let os_version: String?
    let app_version: String?
    let device_name: String?
}

/// `kind: "hello"` — first client → agent message after pairing.
struct Hello: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
    let device_info: DeviceInfo
}

/// `kind: "inbox_request"` — client → agent (payloads.md §4.6).
/// Sent on every (re)connection after `auth_ok` to request a fresh
/// targeted `inbox_update` snapshot from the agent.  Idempotent and
/// side-effect-free, so safe to send unconditionally.
struct InboxRequest: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
}

/// `kind: "approval_response"` — client → agent (payloads.md §4.2).
struct ApprovalResponse: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
    let request_id: String
    let decision: String   // "approved" | "rejected"
    let reason: String?
}

/// `kind: "clarification_response"` — client → agent (payloads.md §4.3).
struct ClarificationResponse: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
    let request_id: String
    let answer: String
}

/// `kind: "logout"` — client → agent (payloads.md §4.4).
struct LogoutPayload: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
}

// MARK: - Sum type

/// A type-erased E2E payload, decoded by inspecting the `kind` field.
///
/// We implement a custom `init(from:)` that decodes the envelope first, then
/// switches on `kind` to decode the rest.  Unknown `kind` throws
/// `SkaldError.invalidPayload`.  This pattern lets the rest of the app use
/// one switch to dispatch a payload to the right ViewModel.
enum Payload: Equatable {

    case inboxUpdate(InboxUpdate)
    case notification(Notification)
    case ack(Ack)
    case hello(Hello)
    case inboxRequest(InboxRequest)
    case approvalResponse(ApprovalResponse)
    case clarificationResponse(ClarificationResponse)
    case logout(LogoutPayload)

    /// Convenience accessor for the base envelope (common to every case).
    var envelope: EnvelopeBase {
        switch self {
        case .inboxUpdate(let p):           return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        case .notification(let p):          return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        case .ack(let p):                   return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        case .hello(let p):                 return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        case .inboxRequest(let p):          return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        case .approvalResponse(let p):      return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        case .clarificationResponse(let p): return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        case .logout(let p):                return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
        }
    }
}

// MARK: - Codable conformance for the sum type

extension Payload: Codable {

    private enum CodingKeys: String, CodingKey {
        case v, kind, id, ts
        // The remaining keys are case-specific and decoded in step 2.
    }

    init(from decoder: Decoder) throws {
        // Step 1 — decode the envelope.
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let v   = try container.decode(Int.self,    forKey: .v)
        let kind = try container.decode(String.self, forKey: .kind)
        let id  = try container.decode(String.self, forKey: .id)
        let ts  = try container.decode(Int64.self,  forKey: .ts)

        if v != 1 {
            throw SkaldError.invalidPayload
        }

        // Step 2 — re-decode the same JSON into the matching concrete type.
        // We can't re-decode `decoder` cheaply; instead we pass the decoder
        // through to the concrete type's `init(from:)`.  Since the concrete
        // types share the same envelope fields, this Just Works.
        switch PayloadKind(rawValue: kind) {
        case .inboxUpdate?:
            let p = try InboxUpdate(from: decoder)
            self = .inboxUpdate(p)
        case .notification?:
            let p = try Notification(from: decoder)
            self = .notification(p)
        case .ack?:
            let p = try Ack(from: decoder)
            self = .ack(p)
        case .hello?:
            let p = try Hello(from: decoder)
            self = .hello(p)
        case .inboxRequest?:
            let p = try InboxRequest(from: decoder)
            self = .inboxRequest(p)
        case .approvalResponse?:
            let p = try ApprovalResponse(from: decoder)
            self = .approvalResponse(p)
        case .clarificationResponse?:
            let p = try ClarificationResponse(from: decoder)
            self = .clarificationResponse(p)
        case .logout?:
            let p = try LogoutPayload(from: decoder)
            self = .logout(p)
        case nil:
            // Forward-compat: unknown kind → not a fatal error per the spec,
            // but we expose it as an error so the caller can decide (log
            // and drop).  The struct shape is otherwise valid.
            _ = (v, id, ts)   // silence "unused" if the compiler complains
            throw SkaldError.invalidPayload
        }
    }

    func encode(to encoder: Encoder) throws {
        // Delegate to the concrete type's encoder.
        switch self {
        case .inboxUpdate(let p):           try p.encode(to: encoder)
        case .notification(let p):          try p.encode(to: encoder)
        case .ack(let p):                   try p.encode(to: encoder)
        case .hello(let p):                 try p.encode(to: encoder)
        case .inboxRequest(let p):          try p.encode(to: encoder)
        case .approvalResponse(let p):      try p.encode(to: encoder)
        case .clarificationResponse(let p): try p.encode(to: encoder)
        case .logout(let p):                try p.encode(to: encoder)
        }
    }
}
