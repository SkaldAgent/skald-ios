//
//  PipeMsgPack.swift
//  Skald
//
//  Minimal MsgPack encoder/decoder (named-map style) for pipe protocol messages.
//  Wire-compatible with rmp-serde's `to_vec_named` / `from_slice` on the Rust side.
//
//  See docs/relay/pipe.md §2 and crates/skald-relay-common/src/pipe.rs.
//

import Foundation

// MARK: - Errors

enum PipeMsgPackError: Error {
    case unexpectedEOF
    case malformed(String)
    case invalidLength(String)
}

// MARK: - MsgPack value tree (intermediate representation)

/// A MsgPack value node. Used as the intermediate representation during
/// encoding and decoding. The pipe types convert to/from this tree.
indirect enum PipeMsgPackValue {
    case nilValue
    case bool(Bool)
    case int(Int64)
    case uint(UInt64)
    case string(String)
    case binary(Data)
    case array([PipeMsgPackValue])
    case map([(String, PipeMsgPackValue)])
}

// MARK: - Encoder

/// Minimal MsgPack encoder (named-map style) for pipe protocol messages.
enum PipeMsgPackEncoder {

    /// Encode a map of string→value pairs.
    static func encode(_ pairs: [(String, PipeMsgPackValue)]) -> Data {
        var buf = Data()
        encodeMapHeader(&buf, count: pairs.count)
        for (key, value) in pairs {
            encodeString(&buf, key)
            encodeValue(&buf, value)
        }
        return buf
    }

    // MARK: Internals

    private static func encodeMapHeader(_ buf: inout Data, count: Int) {
        if count <= 15 {
            buf.append(0x80 | UInt8(count))
        } else if count <= 65535 {
            buf.append(0xDE)
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        } else {
            // map32: we won't need this for pipe types
            buf.append(0xDF)
            buf.append(UInt8((count >> 24) & 0xFF))
            buf.append(UInt8((count >> 16) & 0xFF))
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        }
    }

    private static func encodeArrayHeader(_ buf: inout Data, count: Int) {
        if count <= 15 {
            buf.append(0x90 | UInt8(count))
        } else if count <= 65535 {
            buf.append(0xDC)
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        } else {
            buf.append(0xDD)
            buf.append(UInt8((count >> 24) & 0xFF))
            buf.append(UInt8((count >> 16) & 0xFF))
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        }
    }

    private static func encodeString(_ buf: inout Data, _ str: String) {
        let utf8 = str.utf8
        let count = utf8.count
        if count <= 31 {
            buf.append(0xA0 | UInt8(count))
        } else if count <= 255 {
            buf.append(0xD9)
            buf.append(UInt8(count))
        } else if count <= 65535 {
            buf.append(0xDA)
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        } else {
            buf.append(0xDB)
            buf.append(UInt8((count >> 24) & 0xFF))
            buf.append(UInt8((count >> 16) & 0xFF))
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        }
        buf.append(contentsOf: utf8)
    }

    private static func encodeBinary(_ buf: inout Data, _ data: Data) {
        let count = data.count
        if count <= 255 {
            buf.append(0xC4)
            buf.append(UInt8(count))
        } else if count <= 65535 {
            buf.append(0xC5)
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        } else {
            buf.append(0xC6)
            buf.append(UInt8((count >> 24) & 0xFF))
            buf.append(UInt8((count >> 16) & 0xFF))
            buf.append(UInt8((count >> 8) & 0xFF))
            buf.append(UInt8(count & 0xFF))
        }
        buf.append(data)
    }

    private static func encodeValue(_ buf: inout Data, _ value: PipeMsgPackValue) {
        switch value {
        case .nilValue:
            buf.append(0xC0)
        case .bool(let b):
            buf.append(b ? 0xC3 : 0xC2)
        case .int(let i):
            if i >= 0 {
                encodeUInt(&buf, UInt64(i))
            } else if i >= -32 {
                buf.append(UInt8(bitPattern: Int8(i)))
            } else if i >= Int64(Int8.min) {
                buf.append(0xD0)
                buf.append(UInt8(bitPattern: Int8(i)))
            } else if i >= Int64(Int16.min) {
                buf.append(0xD1)
                var be = Int16(i).bigEndian
                withUnsafeBytes(of: &be) { buf.append(contentsOf: $0) }
            } else if i >= Int64(Int32.min) {
                buf.append(0xD2)
                var be = Int32(i).bigEndian
                withUnsafeBytes(of: &be) { buf.append(contentsOf: $0) }
            } else {
                buf.append(0xD3)
                var be = i.bigEndian
                withUnsafeBytes(of: &be) { buf.append(contentsOf: $0) }
            }
        case .uint(let u):
            encodeUInt(&buf, u)
        case .string(let s):
            encodeString(&buf, s)
        case .binary(let d):
            encodeBinary(&buf, d)
        case .array(let arr):
            encodeArrayHeader(&buf, count: arr.count)
            for v in arr { encodeValue(&buf, v) }
        case .map(let pairs):
            encodeMapHeader(&buf, count: pairs.count)
            for (k, v) in pairs {
                encodeString(&buf, k)
                encodeValue(&buf, v)
            }
        }
    }

    private static func encodeUInt(_ buf: inout Data, _ v: UInt64) {
        if v <= 127 {
            buf.append(UInt8(v))
        } else if v <= 255 {
            buf.append(0xCC)
            buf.append(UInt8(v))
        } else if v <= 65535 {
            buf.append(0xCD)
            buf.append(UInt8((v >> 8) & 0xFF))
            buf.append(UInt8(v & 0xFF))
        } else if v <= 4294967295 {
            buf.append(0xCE)
            buf.append(UInt8((v >> 24) & 0xFF))
            buf.append(UInt8((v >> 16) & 0xFF))
            buf.append(UInt8((v >> 8) & 0xFF))
            buf.append(UInt8(v & 0xFF))
        } else {
            buf.append(0xCF)
            buf.append(UInt8((v >> 56) & 0xFF))
            buf.append(UInt8((v >> 48) & 0xFF))
            buf.append(UInt8((v >> 40) & 0xFF))
            buf.append(UInt8((v >> 32) & 0xFF))
            buf.append(UInt8((v >> 24) & 0xFF))
            buf.append(UInt8((v >> 16) & 0xFF))
            buf.append(UInt8((v >> 8) & 0xFF))
            buf.append(UInt8(v & 0xFF))
        }
    }

    // MARK: Convenience — pipe type encoders

    static func encodeInvite(_ inv: PipeInvite) -> Data {
        encode([
            ("connection_id", .binary(inv.connectionId)),
            ("suite", .string(inv.suite.rawValue)),
            ("handshake", .binary(inv.handshake)),
            ("stream_type", .string(inv.streamType)),
            ("compress", .array(inv.compress.map { .string($0.rawValue) })),
            ("headers", .map(inv.headers.map { ($0.key, .string($0.value)) }))
        ])
    }

    static func encodeAccept(_ acc: PipeAccept) -> Data {
        encode([
            ("connection_id", .binary(acc.connectionId)),
            ("suite", .string(acc.suite.rawValue)),
            ("handshake", .binary(acc.handshake)),
            ("compress", .string(acc.compress.rawValue))
        ])
    }

    static func encodeReject(_ rej: PipeReject) -> Data {
        encode([
            ("connection_id", .binary(rej.connectionId)),
            ("reason", .string(rej.reason))
        ])
    }

    static func encodeChallenge(_ ch: PipeChallenge) -> Data {
        encode([
            ("nonce", .binary(ch.nonce))
        ])
    }

    static func encodeAuth(_ auth: PipeAuth) -> Data {
        encode([
            ("connection_id", .binary(auth.connectionId)),
            ("pubkey", .binary(auth.pubkey)),
            ("dest", .binary(auth.dest)),
            ("namespace_id", .binary(auth.namespaceId)),
            ("signature", .binary(auth.signature))
        ])
    }
}

// MARK: - Decoder

/// Minimal MsgPack decoder for pipe protocol messages.
enum PipeMsgPackDecoder {

    // MARK: - Top-level

    /// Decode a map, returning key-value pairs.
    static func decode(_ data: Data) throws -> [(String, PipeMsgPackValue)] {
        var cursor = Cursor(data: data)
        let value = try decodeNext(&cursor)
        guard case .map(let pairs) = value else {
            throw PipeMsgPackError.malformed("expected map")
        }
        return pairs
    }

    // MARK: - Internals

    private struct Cursor {
        let data: Data
        var offset: Int = 0

        var remaining: Int { data.count - offset }

        mutating func readByte() throws -> UInt8 {
            guard offset < data.count else { throw PipeMsgPackError.unexpectedEOF }
            let b = data[offset]
            offset += 1
            return b
        }

        mutating func readBytes(_ n: Int) throws -> Data {
            guard offset + n <= data.count else { throw PipeMsgPackError.unexpectedEOF }
            let bytes = data.subdata(in: offset..<(offset + n))
            offset += n
            return bytes
        }
    }

    private static func decodeNext(_ c: inout Cursor) throws -> PipeMsgPackValue {
        let fb = try c.readByte()

        switch fb {
        // nil
        case 0xC0:
            return .nilValue
        // false
        case 0xC2:
            return .bool(false)
        // true
        case 0xC3:
            return .bool(true)

        // bin 8 / 16 / 32
        case 0xC4:
            let len = Int(try c.readByte())
            return .binary(try c.readBytes(len))
        case 0xC5:
            let hi = Int(try c.readByte())
            let lo = Int(try c.readByte())
            return .binary(try c.readBytes((hi << 8) | lo))
        case 0xC6:
            let b0 = Int(try c.readByte())
            let b1 = Int(try c.readByte())
            let b2 = Int(try c.readByte())
            let b3 = Int(try c.readByte())
            return .binary(try c.readBytes((b0 << 24) | (b1 << 16) | (b2 << 8) | b3))

        // Positive fixint 0x00..0x7F
        case 0x00...0x7F:
            return .uint(UInt64(fb))

        // Negative fixint 0xE0..0xFF
        case 0xE0...0xFF:
            return .int(Int64(Int8(bitPattern: fb)))

        // fixmap 0x80..0x8F
        case 0x80...0x8F:
            let count = Int(fb & 0x0F)
            return try decodeMap(&c, count: count)

        // fixarray 0x90..0x9F
        case 0x90...0x9F:
            let count = Int(fb & 0x0F)
            return try decodeArray(&c, count: count)

        // fixstr 0xA0..0xBF
        case 0xA0...0xBF:
            let len = Int(fb & 0x1F)
            let bytes = try c.readBytes(len)
            guard let str = String(data: bytes, encoding: .utf8) else {
                throw PipeMsgPackError.malformed("invalid UTF-8 in string")
            }
            return .string(str)

        // uint 8
        case 0xCC:
            return .uint(UInt64(try c.readByte()))
        // uint 16
        case 0xCD:
            let hi = UInt64(try c.readByte())
            let lo = UInt64(try c.readByte())
            return .uint((hi << 8) | lo)
        // uint 32
        case 0xCE:
            let b0 = UInt64(try c.readByte())
            let b1 = UInt64(try c.readByte())
            let b2 = UInt64(try c.readByte())
            let b3 = UInt64(try c.readByte())
            return .uint((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
        // uint 64
        case 0xCF:
            let b0 = UInt64(try c.readByte())
            let b1 = UInt64(try c.readByte())
            let b2 = UInt64(try c.readByte())
            let b3 = UInt64(try c.readByte())
            let b4 = UInt64(try c.readByte())
            let b5 = UInt64(try c.readByte())
            let b6 = UInt64(try c.readByte())
            let b7 = UInt64(try c.readByte())
            return .uint((b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) |
                         (b4 << 24) | (b5 << 16) | (b6 << 8) | b7)

        // int 8
        case 0xD0:
            return .int(Int64(Int8(bitPattern: try c.readByte())))
        // int 16
        case 0xD1:
            let bytes = try c.readBytes(2)
            let i = bytes.startIndex
            let raw16 = UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1])
            return .int(Int64(Int16(bitPattern: raw16)))
        // int 32
        case 0xD2:
            let bytes = try c.readBytes(4)
            let i = bytes.startIndex
            let raw32 = UInt32(bytes[i]) << 24 | UInt32(bytes[i + 1]) << 16
                      | UInt32(bytes[i + 2]) << 8 | UInt32(bytes[i + 3])
            return .int(Int64(Int32(bitPattern: raw32)))
        // int 64
        case 0xD3:
            let bytes = try c.readBytes(8)
            let i = bytes.startIndex
            let raw64 = UInt64(bytes[i]) << 56 | UInt64(bytes[i + 1]) << 48
                      | UInt64(bytes[i + 2]) << 40 | UInt64(bytes[i + 3]) << 32
                      | UInt64(bytes[i + 4]) << 24 | UInt64(bytes[i + 5]) << 16
                      | UInt64(bytes[i + 6]) << 8  | UInt64(bytes[i + 7])
            return .int(Int64(bitPattern: raw64))

        // str 8
        case 0xD9:
            let len = Int(try c.readByte())
            let bytes = try c.readBytes(len)
            guard let str = String(data: bytes, encoding: .utf8) else {
                throw PipeMsgPackError.malformed("invalid UTF-8 in string")
            }
            return .string(str)
        // str 16
        case 0xDA:
            let hi = Int(try c.readByte())
            let lo = Int(try c.readByte())
            let len = (hi << 8) | lo
            let bytes = try c.readBytes(len)
            guard let str = String(data: bytes, encoding: .utf8) else {
                throw PipeMsgPackError.malformed("invalid UTF-8 in string")
            }
            return .string(str)
        // str 32
        case 0xDB:
            let b0 = Int(try c.readByte())
            let b1 = Int(try c.readByte())
            let b2 = Int(try c.readByte())
            let b3 = Int(try c.readByte())
            let len = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
            let bytes = try c.readBytes(len)
            guard let str = String(data: bytes, encoding: .utf8) else {
                throw PipeMsgPackError.malformed("invalid UTF-8 in string")
            }
            return .string(str)

        // array 16
        case 0xDC:
            let hi = Int(try c.readByte())
            let lo = Int(try c.readByte())
            return try decodeArray(&c, count: (hi << 8) | lo)
        // array 32
        case 0xDD:
            let b0 = Int(try c.readByte())
            let b1 = Int(try c.readByte())
            let b2 = Int(try c.readByte())
            let b3 = Int(try c.readByte())
            return try decodeArray(&c, count: (b0 << 24) | (b1 << 16) | (b2 << 8) | b3)

        // map 16
        case 0xDE:
            let hi = Int(try c.readByte())
            let lo = Int(try c.readByte())
            return try decodeMap(&c, count: (hi << 8) | lo)
        // map 32
        case 0xDF:
            let b0 = Int(try c.readByte())
            let b1 = Int(try c.readByte())
            let b2 = Int(try c.readByte())
            let b3 = Int(try c.readByte())
            return try decodeMap(&c, count: (b0 << 24) | (b1 << 16) | (b2 << 8) | b3)

        // float 32 / 64 (unused by pipe, but decode as nil for forward-compat)
        case 0xCA:
            _ = try c.readBytes(4)
            return .nilValue
        case 0xCB:
            _ = try c.readBytes(8)
            return .nilValue

        default:
            throw PipeMsgPackError.malformed("unknown format byte 0x\(String(fb, radix: 16))")
        }
    }

    private static func decodeMap(_ c: inout Cursor, count: Int) throws -> PipeMsgPackValue {
        var pairs: [(String, PipeMsgPackValue)] = []
        pairs.reserveCapacity(count)
        for _ in 0..<count {
            // Each map entry: key (string), value
            let keyVal = try decodeNext(&c)
            guard case .string(let key) = keyVal else {
                throw PipeMsgPackError.malformed("map key must be string")
            }
            let val = try decodeNext(&c)
            pairs.append((key, val))
        }
        return .map(pairs)
    }

    private static func decodeArray(_ c: inout Cursor, count: Int) throws -> PipeMsgPackValue {
        var items: [PipeMsgPackValue] = []
        items.reserveCapacity(count)
        for _ in 0..<count {
            items.append(try decodeNext(&c))
        }
        return .array(items)
    }

    // MARK: Convenience — pipe type decoders

    /// Decode a PipeSignal from MsgPack. The wire format is externally tagged:
    /// `{"Invite":{...}}` / `{"Accept":{...}}` / `{"Reject":{...}}`
    static func decodeSignal(_ data: Data) throws -> PipeSignal {
        let pairs = try decode(data)
        guard let first = pairs.first, pairs.count == 1 else {
            throw PipeMsgPackError.malformed("expected single-entry map for PipeSignal")
        }
        switch first.0 {
        case "Invite":
            guard case .map(let fields) = first.1 else {
                throw PipeMsgPackError.malformed("Invite body must be a map")
            }
            return .invite(try decodeInvite(from: fields))
        case "Accept":
            guard case .map(let fields) = first.1 else {
                throw PipeMsgPackError.malformed("Accept body must be a map")
            }
            return .accept(try decodeAccept(from: fields))
        case "Reject":
            guard case .map(let fields) = first.1 else {
                throw PipeMsgPackError.malformed("Reject body must be a map")
            }
            return .reject(try decodeReject(from: fields))
        default:
            throw PipeMsgPackError.malformed("unknown pipe signal variant: \(first.0)")
        }
    }

    static func decodeInvite(_ data: Data) throws -> PipeInvite {
        let pairs = try decode(data)
        return try decodeInvite(from: pairs)
    }

    static func decodeAccept(_ data: Data) throws -> PipeAccept {
        let pairs = try decode(data)
        return try decodeAccept(from: pairs)
    }

    static func decodeReject(_ data: Data) throws -> PipeReject {
        let pairs = try decode(data)
        return try decodeReject(from: pairs)
    }

    static func decodeChallenge(_ data: Data) throws -> PipeChallenge {
        let pairs = try decode(data)
        return try decodeChallenge(from: pairs)
    }

    static func decodeAuth(_ data: Data) throws -> PipeAuth {
        let pairs = try decode(data)
        return try decodeAuth(from: pairs)
    }

    // MARK: Internal decoders (from key-value pairs)

    private static func decodeInvite(from pairs: [(String, PipeMsgPackValue)]) throws -> PipeInvite {
        let dict = pairsToDict(pairs)
        let cid = try requireBin(dict, "connection_id", length: 32)
        let suite = try requireSuite(dict)
        let handshake = try requireBin(dict, "handshake", length: 32)
        let streamType = try requireString(dict, "stream_type")
        let compress = try requireCompressList(dict)
        let headers = try requireStringMap(dict, "headers")
        return PipeInvite(
            connectionId: cid, suite: suite, handshake: handshake,
            streamType: streamType, compress: compress, headers: headers
        )
    }

    private static func decodeAccept(from pairs: [(String, PipeMsgPackValue)]) throws -> PipeAccept {
        let dict = pairsToDict(pairs)
        let cid = try requireBin(dict, "connection_id", length: 32)
        let suite = try requireSuite(dict)
        let handshake = try requireBin(dict, "handshake", length: 32)
        let compress = try requireCompress(dict)
        return PipeAccept(connectionId: cid, suite: suite, handshake: handshake, compress: compress)
    }

    private static func decodeReject(from pairs: [(String, PipeMsgPackValue)]) throws -> PipeReject {
        let dict = pairsToDict(pairs)
        let cid = try requireBin(dict, "connection_id", length: 32)
        let reason = try requireString(dict, "reason")
        return PipeReject(connectionId: cid, reason: reason)
    }

    private static func decodeChallenge(from pairs: [(String, PipeMsgPackValue)]) throws -> PipeChallenge {
        let dict = pairsToDict(pairs)
        let nonce = try requireBin(dict, "nonce", length: 32)
        return PipeChallenge(nonce: nonce)
    }

    private static func decodeAuth(from pairs: [(String, PipeMsgPackValue)]) throws -> PipeAuth {
        let dict = pairsToDict(pairs)
        return PipeAuth(
            connectionId: try requireBin(dict, "connection_id", length: 32),
            pubkey:      try requireBin(dict, "pubkey", length: 32),
            dest:        try requireBin(dict, "dest", length: 32),
            namespaceId: try requireBin(dict, "namespace_id", length: 32),
            signature:   try requireBin(dict, "signature", length: 64)
        )
    }

    // MARK: - Helpers

    private static func pairsToDict(_ pairs: [(String, PipeMsgPackValue)]) -> [String: PipeMsgPackValue] {
        Dictionary(pairs, uniquingKeysWith: { _, last in last })
    }

    private static func requireBin(_ dict: [String: PipeMsgPackValue], _ key: String, length: Int) throws -> Data {
        guard case .binary(let data) = dict[key] else {
            throw PipeMsgPackError.malformed("missing or wrong type for field '\(key)'")
        }
        guard data.count == length else {
            throw PipeMsgPackError.invalidLength("field '\(key)' expected \(length)B, got \(data.count)B")
        }
        return data
    }

    private static func requireString(_ dict: [String: PipeMsgPackValue], _ key: String) throws -> String {
        guard case .string(let s) = dict[key] else {
            throw PipeMsgPackError.malformed("missing or wrong type for field '\(key)'")
        }
        return s
    }

    private static func requireSuite(_ dict: [String: PipeMsgPackValue]) throws -> PipeSuite {
        let s = try requireString(dict, "suite")
        guard let suite = PipeSuite(rawValue: s) else {
            throw PipeMsgPackError.malformed("unknown pipe suite: \(s)")
        }
        return suite
    }

    private static func requireCompress(_ dict: [String: PipeMsgPackValue]) throws -> PipeCompress {
        let s = try requireString(dict, "compress")
        guard let comp = PipeCompress(rawValue: s) else {
            throw PipeMsgPackError.malformed("unknown pipe compress: \(s)")
        }
        return comp
    }

    private static func requireCompressList(_ dict: [String: PipeMsgPackValue]) throws -> [PipeCompress] {
        guard case .array(let arr) = dict["compress"] else {
            throw PipeMsgPackError.malformed("missing or wrong type for field 'compress'")
        }
        return try arr.map { val in
            guard case .string(let s) = val,
                  let comp = PipeCompress(rawValue: s) else {
                throw PipeMsgPackError.malformed("invalid compress value in array")
            }
            return comp
        }
    }

    private static func requireStringMap(_ dict: [String: PipeMsgPackValue], _ key: String) throws -> [String: String] {
        guard case .map(let pairs) = dict[key] else {
            // headers may be absent (default empty)
            return [:]
        }
        var result: [String: String] = [:]
        for (k, v) in pairs {
            guard case .string(let val) = v else {
                throw PipeMsgPackError.malformed("header value must be string")
            }
            result[k] = val
        }
        return result
    }
}

// MARK: - PipeSignal encode/decode convenience

extension PipeSignal {
    func encode() -> Data {
        switch self {
        case .invite(let inv):
            return PipeMsgPackEncoder.encode([("Invite", .map([
                ("connection_id", .binary(inv.connectionId)),
                ("suite", .string(inv.suite.rawValue)),
                ("handshake", .binary(inv.handshake)),
                ("stream_type", .string(inv.streamType)),
                ("compress", .array(inv.compress.map { .string($0.rawValue) })),
                ("headers", .map(inv.headers.map { ($0.key, .string($0.value)) }))
            ]))])
        case .accept(let acc):
            return PipeMsgPackEncoder.encode([("Accept", .map([
                ("connection_id", .binary(acc.connectionId)),
                ("suite", .string(acc.suite.rawValue)),
                ("handshake", .binary(acc.handshake)),
                ("compress", .string(acc.compress.rawValue))
            ]))])
        case .reject(let rej):
            return PipeMsgPackEncoder.encode([("Reject", .map([
                ("connection_id", .binary(rej.connectionId)),
                ("reason", .string(rej.reason))
            ]))])
        }
    }

    static func decode(from data: Data) throws -> PipeSignal {
        try PipeMsgPackDecoder.decodeSignal(data)
    }
}

// MARK: - Additional encode/decode convenience

extension PipeChallenge {
    func encode() -> Data { PipeMsgPackEncoder.encodeChallenge(self) }
    static func decode(from data: Data) throws -> PipeChallenge { try PipeMsgPackDecoder.decodeChallenge(data) }
}

extension PipeAuth {
    func encode() -> Data { PipeMsgPackEncoder.encodeAuth(self) }
    static func decode(from data: Data) throws -> PipeAuth { try PipeMsgPackDecoder.decodeAuth(data) }
}

extension PipeInvite {
    func encode() -> Data { PipeMsgPackEncoder.encodeInvite(self) }
    static func decode(from data: Data) throws -> PipeInvite { try PipeMsgPackDecoder.decodeInvite(data) }
}

extension PipeAccept {
    func encode() -> Data { PipeMsgPackEncoder.encodeAccept(self) }
    static func decode(from data: Data) throws -> PipeAccept { try PipeMsgPackDecoder.decodeAccept(data) }
}

extension PipeReject {
    func encode() -> Data { PipeMsgPackEncoder.encodeReject(self) }
    static func decode(from data: Data) throws -> PipeReject { try PipeMsgPackDecoder.decodeReject(data) }
}
