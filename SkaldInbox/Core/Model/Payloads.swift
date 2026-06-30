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
    case elicitationResponse   = "elicitation_response"
    case logout                = "logout"
    case ack                   = "ack"
}

// MARK: - JSON value (for decoding arbitrary JSON objects)

/// A recursive JSON value that can represent any JSON type.
/// Used for the `arguments` field in ApprovalItem.
indirect enum JSONValue: Codable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case null
    case array([JSONValue])
    case object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let str = try? container.decode(String.self) {
            self = .string(str)
        } else if let num = try? container.decode(Double.self) {
            self = .number(num)
        } else if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if container.decodeNil() {
            self = .null
        } else if let arr = try? container.decode([JSONValue].self) {
            self = .array(arr)
        } else if let obj = try? container.decode([String: JSONValue].self) {
            self = .object(obj)
        } else {
            throw DecodingError.typeMismatch(
                JSONValue.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Unsupported JSON value"
                )
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let s):  try container.encode(s)
        case .number(let n):  try container.encode(n)
        case .bool(let b):    try container.encode(b)
        case .null:           try container.encodeNil()
        case .array(let a):   try container.encode(a)
        case .object(let o):  try container.encode(o)
        }
    }

    /// Human-readable representation for display.
    var displayValue: String {
        switch self {
        case .string(let s): return s
        case .number(let n):
            return n == floor(n) ? String(Int(n)) : String(n)
        case .bool(let b):   return b ? "true" : "false"
        case .null:          return "null"
        case .array(let a):  return a.map(\.displayValue).joined(separator: ", ")
        case .object(let o): return o.map { "\($0.key): \($0.value.displayValue)" }
                                 .joined(separator: ", ")
        }
    }
}

// MARK: - Agent → Client payloads

/// An item in the pending-approvals list of an `inbox_update`.
struct ApprovalItem: Codable, Equatable {
    let request_id: String
    let tool_name: String
    let agent_label: String
    let summary: String
    let detail: String?
    let arguments: [String: JSONValue]?
    let created_at: Int64   // unix ms
}

/// An item in the pending-clarifications list of an `inbox_update`.
struct ClarificationItem: Codable, Equatable {
    let request_id: String
    let question: String
    let context: String?
    let suggested_answers: [String]?
    let agent_label: String
    let created_at: Int64   // unix ms
}

/// An item in the pending-elicitations list of an `inbox_update`.
///
/// An MCP server requested input the LLM must not see (e.g. an SSH password).
/// Carries only the prompt **metadata** — never the value.  `field_name` is the
/// key the agent expects back inside the response `content`; `sensitive` asks
/// the UI for a masked field; `is_confirmation` means yes/no with no input.
struct ElicitationItem: Codable, Equatable {
    let request_id: String
    let server_name: String
    let message: String
    let field_name: String?
    let sensitive: Bool
    let is_confirmation: Bool
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
    /// Optional for forward/backward-compat: agents that predate MCP
    /// elicitation simply omit the key (decoded as nil → treat as empty).
    let elicitations: [ElicitationItem]?
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

/// `kind: "elicitation_response"` — client → agent.
///
/// Reply to an MCP elicitation.  `content` carries the field values for
/// `action == "accept"` (keyed by the elicitation's `field_name`, fallback
/// `"value"`); it is nil for `"decline"` / `"cancel"`.  The value may be a
/// secret — it is sealed E2E by the session and must never be logged.
struct ElicitationResponse: Codable, Equatable {
    let v: Int
    let kind: String
    let id: String
    let ts: Int64
    let request_id: String
    let action: String              // "accept" | "decline" | "cancel"
    let content: [String: String]?
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
enum Payload: Equatable, Sendable {

    case inboxUpdate(InboxUpdate)
    case notification(Notification)
    case ack(Ack)
    case hello(Hello)
    case inboxRequest(InboxRequest)
    case approvalResponse(ApprovalResponse)
    case clarificationResponse(ClarificationResponse)
    case elicitationResponse(ElicitationResponse)
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
        case .elicitationResponse(let p):   return EnvelopeBase(v: p.v, kind: p.kind, id: p.id, ts: p.ts)
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
        case .elicitationResponse?:
            let p = try ElicitationResponse(from: decoder)
            self = .elicitationResponse(p)
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
        case .elicitationResponse(let p):   try p.encode(to: encoder)
        case .logout(let p):                try p.encode(to: encoder)
        }
    }
}
