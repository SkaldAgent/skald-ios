//
//  KeychainStore.swift
//  Skald
//
//  Keychain wrapper with App Group sharing.
//  All items use:
//   - kSecAttrAccessGroup    = "group.net.skaldagent"     (shared with the NSE)
//   - kSecAttrSynchronizable = false                  (we control replication)
//   - kSecAttrAccessible     = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//
//  This file is compiled into BOTH targets (see project.yml).  Keep it
//  extension-safe: do NOT import UIKit / UserNotifications here.
//

import Foundation
import Security
import os

/// A thread-safe Keychain wrapper backed by the App Group access group.
///
/// All mutation paths are serialised through a single `NSLock` so that
/// `incrementCounter` and `compareAndAdvanceCounter` are atomic with respect
/// to each other — required because `recv_counter` is written by both the
/// app process and the Notification Service Extension.
final class KeychainStore {

    // MARK: Public configuration

    /// Keychain Access Group shared by the app and the NSE.  MUST match the
    /// `keychain-access-groups` array in the entitlements files of both
    /// targets.
    static let accessGroup = "group.net.skaldagent"

    /// `kSecAttrService` value used for every item.
    static let service = "net.skaldagent.inbox"

    // MARK: Known account keys

    enum Key {
        static let seed             = "skald.seed"
        static let namespaceId      = "skald.namespace_id"
        static let relayUrl         = "skald.relay_url"
        static let agentEd25519Pub  = "skald.agent_ed25519_pub"
        static let agentX25519Pub   = "skald.agent_x25519_pub"
        static let sendCounter      = "skald.send_counter"
        static let recvCounter      = "skald.recv_counter"
        static let myEd25519Pub     = "skald.my_ed25519_pub"
        static let myX25519Pub      = "skald.my_x25519_pub"
    }

    // MARK: - Init

    /// Shared singleton.  Both the app and the NSE use the same instance —
    /// the underlying Keychain is the only source of truth, and the lock here
    /// is process-local (the OS serialises the Keychain across processes).
    static let shared = KeychainStore()

    private let lock = NSLock()
    private let log = Logger(subsystem: "net.skaldagent.inbox", category: "Keychain")

    private init() {}

    // MARK: - Generic Data

    /// Persist `data` under `account`, replacing any existing value.
    func setData(_ data: Data, for account: String) throws {
        lock.lock()
        defer { lock.unlock() }

        // Try update first (cheaper, avoids the delete-then-add race).
        let queryUpdate: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
        ]
        let attrs: [String: Any] = [
            kSecValueData as String:   data,
        ]
        let updateStatus = SecItemUpdate(queryUpdate as CFDictionary,
                                         attrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw SkaldError.keychainError(updateStatus)
        }

        // Item missing — add a new one.
        var queryAdd: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      Self.service,
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  Self.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessible as String:   kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String:        data,
        ]
        // `kSecUseDataProtectionKeychain` is required for sharing items via
        // `kSecAttrAccessGroup` on iOS.  Falls back gracefully on older OSes
        // (we target iOS 18, so it is always available).
        queryAdd[kSecUseDataProtectionKeychain as String] = true

        let addStatus = SecItemAdd(queryAdd as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SkaldError.keychainError(addStatus)
        }
    }

    /// Read raw data for `account`, or `nil` if no such item exists.
    func getData(for account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }

        var query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      Self.service,
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  Self.accessGroup,
            kSecReturnData as String:       true,
            kSecMatchLimit as String:       kSecMatchLimitOne,
        ]
        query[kSecUseDataProtectionKeychain as String] = true

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw SkaldError.keychainError(status)
        }
    }

    // MARK: - String convenience

    /// Store a UTF-8 string.
    func setString(_ s: String, for account: String) throws {
        try setData(Data(s.utf8), for: account)
    }

    /// Read a UTF-8 string.  Returns `nil` if the account is missing.
    func getString(for account: String) throws -> String? {
        guard let d = try getData(for: account) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    // MARK: - Deletion

    /// Remove a single account.
    func delete(for account: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      Self.service,
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  Self.accessGroup,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SkaldError.keychainError(status)
        }
    }

    /// Remove every account we own.  Used by Logout.  Items not belonging to
    /// `service`/`accessGroup` are NOT touched.
    func deleteAll() throws {
        lock.lock()
        defer { lock.unlock() }

        let query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      Self.service,
            kSecAttrAccessGroup as String:  Self.accessGroup,
            kSecMatchLimit as String:       kSecMatchLimitAll,
        ]
        let status = SecItemDelete(query as CFDictionary)
        // `errSecItemNotFound` is fine: nothing to delete.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SkaldError.keychainError(status)
        }
    }

    // MARK: - Atomic counter operations

    /// Atomic increment-and-return for a u64 counter stored as 8 big-endian bytes.
    ///
    /// Behaviour:
    /// - If the item is absent, treat the current value as `0`, persist `1`,
    ///   and return `1`.
    /// - If present, read it, add `1`, persist the new value, and return the
    ///   NEW value.
    ///
    /// MUST be thread-safe across threads of the same process (NSLock).
    /// Across processes (app ↔ NSE) the OS-level Keychain is the synchroniser.
    func incrementCounter(for account: String) throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }

        let current: UInt64
        if let raw = try readCounterUnlocked(account) {
            current = raw
        } else {
            current = 0
        }
        let next = current &+ 1   // wrapping add (UInt64 wraps per language rules)
        try writeCounterUnlocked(account, value: next)
        return next
    }

    /// Compare-and-set "only forward" — used for `recv_counter`, which can be
    /// written by both the app and the NSE.  Only updates the stored value if
    /// `newValue > current`.  Returns the resulting value (either the
    /// unchanged old one, or `newValue`).
    func compareAndAdvanceCounter(for account: String, to newValue: UInt64) throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }

        let current: UInt64 = (try readCounterUnlocked(account)) ?? 0
        if newValue > current {
            try writeCounterUnlocked(account, value: newValue)
            return newValue
        }
        return current
    }

    // MARK: - Counter helpers (caller MUST hold `lock`)

    /// Read a u64 BE counter.  Returns `nil` if absent.
    private func readCounterUnlocked(_ account: String) throws -> UInt64? {
        var query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      Self.service,
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  Self.accessGroup,
            kSecReturnData as String:       true,
            kSecMatchLimit as String:       kSecMatchLimitOne,
        ]
        query[kSecUseDataProtectionKeychain as String] = true

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let raw = item as? Data else { return nil }
            guard raw.count == 8 else {
                log.error("counter \(account, privacy: .public) has wrong length: \(raw.count, privacy: .public)")
                return nil
            }
            var v: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &v) { dst in
                raw.copyBytes(to: dst)
            }
            return UInt64(bigEndian: v)
        case errSecItemNotFound:
            return nil
        default:
            throw SkaldError.keychainError(status)
        }
    }

    /// Write a u64 counter as 8 big-endian bytes.
    private func writeCounterUnlocked(_ account: String, value: UInt64) throws {
        var be = value.bigEndian
        let data = withUnsafeBytes(of: &be) { Data($0) }
        try setDataUnlocked(data, for: account)
    }

    /// Variant of `setData` that does NOT take the lock.  Used by the counter
    /// helpers that already hold it.
    private func setDataUnlocked(_ data: Data, for account: String) throws {
        let queryUpdate: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
        ]
        let attrs: [String: Any] = [
            kSecValueData as String:   data,
        ]
        let updateStatus = SecItemUpdate(queryUpdate as CFDictionary,
                                         attrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw SkaldError.keychainError(updateStatus)
        }

        var queryAdd: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        Self.service,
            kSecAttrAccount as String:        account,
            kSecAttrAccessGroup as String:    Self.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessible as String:     kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String:          data,
        ]
        queryAdd[kSecUseDataProtectionKeychain as String] = true

        let addStatus = SecItemAdd(queryAdd as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SkaldError.keychainError(addStatus)
        }
    }
}
