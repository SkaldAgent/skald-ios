//
//  NotificationService.swift
//  NotificationServiceExtension
//
//  Decrypts the E2E payload carried by a `mutable-content` push and builds a
//  rich `UNNotificationContent`.  Runs in a separate process (~24 MB / ~30 s
//  budget).  Never opens a network connection.
//
//  Flow (ios-app.md §8.2, crypto.md §4-§7):
//   1. Load seed from App-Group Keychain → derive keys.
//   2. aes_key = HKDF(ECDH(my_x25519_priv, agent_x25519_pub))
//   3. aad = ns_raw ‖ from_pub(agent ed25519) ‖ my_pub(client ed25519)
//   4. plaintext = AES-256-GCM.open(aes_key, nonce, aad, ct‖tag)
//   5. Decode `Payload` → first pending item → rich content.
//   6. Persist `recv_counter` (atomic CAS) after a successful open.
//
//  On any failure (decryption, key material missing, etc.) the user gets a
//  generic "Action required" notification — no sensitive content leaks.
//

import UserNotifications
import Foundation
import CryptoKit
import os

@objc(NotificationService)
final class NotificationService: UNNotificationServiceExtension {

    // MARK: - State

    private let log = Logger(subsystem: "net.skaldagent.inbox.nse", category: "decrypt")

    /// Process-local dedup of `request_id`s already rendered into a rich
    /// notification.  The NSE process is short-lived and only one instance
    /// typically runs at a time, so a simple in-memory set is enough for v1.
    private static var shownRequestIDs = Set<String>()

    // MARK: - UNNotificationServiceExtension

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {

        let bestAttempt = (request.content.mutableCopy() as? UNMutableNotificationContent)
            ?? UNMutableNotificationContent()
        bestAttempt.categoryIdentifier = "skald_inbox"

        /// Render a generic, content-free notification and deliver it.
        func showGeneric(_ kind: String, extra: [String: Any] = [:]) {
            bestAttempt.title = "Skald"
            bestAttempt.body = String(localized: "Action required")
            var info: [String: Any] = ["kind": kind]
            for (k, v) in extra { info[k] = v }
            bestAttempt.userInfo = info
            contentHandler(bestAttempt)
        }

        // ----- 1. Parse the userInfo envelope -----

        guard let userInfo = request.content.userInfo as? [String: Any],
              let dAny = userInfo["d"] as? [String: Any] else {
            showGeneric("malformed")
            return
        }

        // ----- 2. Wake-only push (no ciphertext) -----

        if let wake = dAny["wake"] as? Bool, wake == true {
            bestAttempt.title = "Skald"
            bestAttempt.body = String(localized: "Open to see what's new")
            bestAttempt.userInfo = ["kind": "wake"]
            contentHandler(bestAttempt)
            return
        }

        // ----- 3. E2E push: read the envelope fields -----

        guard let nsHex = dAny["ns"] as? String,
              let fromHex = dAny["from"] as? String,
              let nHex = dAny["n"] as? String,
              let cB64 = dAny["c"] as? String else {
            showGeneric("malformed")
            return
        }

        // ----- 4. Decrypt + render -----

        do {
            // 4a. Load seed + derived keys.
            let seed = try KeyManager.shared.loadOrCreateSeed()
            let keypair = try KeyManager.shared.deriveKeys(seed: seed)

            // 4b. Read agent identity and namespace from the App-Group Keychain.
            //     Any missing piece means we are not paired → generic.
            guard let agentEd = try KeychainStore.shared.getData(for: KeychainStore.Key.agentEd25519Pub),
                  let agentX  = try KeychainStore.shared.getData(for: KeychainStore.Key.agentX25519Pub),
                  let nsRaw   = try KeychainStore.shared.getData(for: KeychainStore.Key.namespaceId),
                  let myEdRaw = try KeychainStore.shared.getData(for: KeychainStore.Key.myEd25519Pub) else {
                throw SkaldError.invalidKey
            }

            // 4c. Build the engine.
            let engine = CryptoEngine(
                agentX25519Pub: agentX,
                agentEd25519Pub: agentEd,
                myX25519Priv: keypair.agreement,
                myEd25519Pub: myEdRaw,
                namespaceIdRaw: nsRaw
            )

            // 4d. Decode envelope fields.
            let fromBytes = try Hex.decode(fromHex)
            let nonce     = try Hex.decode(nHex)
            let sealed    = try Base64.decode(cB64)

            // 4e. Read the last-seen counter (8 BE bytes; 0 if absent).
            //     The keychain is shared with the main app, so a stale read
            //     would only ever make us MORE strict (older counter → reject
            //     more as replays).  The engine calls this closure once.
            let lastSeen: UInt64 = {
                guard let raw = try? KeychainStore.shared.getData(for: KeychainStore.Key.recvCounter),
                      raw.count == 8 else { return 0 }
                return raw.withUnsafeBytes { $0.load(as: UInt64.self) }.bigEndian
            }()

            // 4f. Decrypt + authenticate.  We do NOT advance `recv_counter`
            //     here: the queued message is also delivered to the app via
            //     WS when the user opens it, and the app's own `engine.open`
            //     must accept it (counter-replay would drop the whole inbox
            //     update).  The NSE's job is just to render a rich alert;
            //     persisting counter state is the app's responsibility.
            let plaintext = try engine.open(
                nonce: nonce,
                sealed: sealed,
                direction: CryptoConstants.nonceDirAgentToClient,
                lastSeenCounter: { lastSeen },
                updateLastSeen: { _ in /* NSE: do not persist counter */ },
                fromEd25519Pub: fromBytes,
                toEd25519Pub: myEdRaw
            )

            // 4g. Decode the plaintext payload.
            let payload = try JSONDecoder().decode(Payload.self, from: plaintext)

            // 4h. Render rich content.  We only ever show ONE item — the NSE
            //     has a tight memory/time budget and must not buffer the full
            //     inbox.
            switch payload {
            case .inboxUpdate(let u):
                // Badge is per-render only; the app icon badge is set by the
                // app when it comes to the foreground.
                bestAttempt.badge = NSNumber(value: u.badge)

                if let approval = u.approvals.first {
                    let rid = approval.request_id
                    if Self.shownRequestIDs.contains(rid) {
                        // Already shown in this NSE process → suppress
                        // duplicates (the app will fetch the real state on
                        // open).
                        showGeneric("dedup", extra: ["request_id": rid])
                        return
                    }
                    Self.shownRequestIDs.insert(rid)
                    bestAttempt.title = "🔔 \(approval.tool_name)"
                    bestAttempt.body = approval.summary
                    if let detail = approval.detail { bestAttempt.subtitle = detail }
                    bestAttempt.userInfo = [
                        "request_id": rid,
                        "kind": "approval",
                        "tool_name": approval.tool_name
                    ]
                } else if let clar = u.clarifications.first {
                    let rid = clar.request_id
                    if Self.shownRequestIDs.contains(rid) {
                        showGeneric("dedup", extra: ["request_id": rid])
                        return
                    }
                    Self.shownRequestIDs.insert(rid)
                    bestAttempt.title = String(localized: "💬 Clarification")
                    bestAttempt.body = clar.question
                    if let context = clar.context { bestAttempt.subtitle = context }
                    bestAttempt.userInfo = [
                        "request_id": rid,
                        "kind": "clarification"
                    ]
                } else if let elic = u.elicitations?.first {
                    let rid = elic.request_id
                    // Prefix the dedup key by type: elicitation rowids live in a
                    // different table and could collide with an approval/clar id.
                    let dedupKey = "elic:\(rid)"
                    if Self.shownRequestIDs.contains(dedupKey) {
                        showGeneric("dedup", extra: ["request_id": rid])
                        return
                    }
                    Self.shownRequestIDs.insert(dedupKey)
                    // Use the elicitation category so the alert offers the
                    // "Enter secret" / "Decline" actions, not approve/reject.
                    bestAttempt.categoryIdentifier = "skald_elicitation"
                    bestAttempt.title = "🔐 \(elic.server_name)"
                    bestAttempt.body = elic.message      // prompt only — never the secret
                    bestAttempt.userInfo = [
                        "request_id": rid,
                        "kind": "elicitation"
                    ]
                } else {
                    // Empty inbox — nothing rich to show.
                    showGeneric("empty")
                    return
                }

            case .notification(let n):
                bestAttempt.title = n.title
                bestAttempt.body = n.body
                bestAttempt.userInfo = ["kind": "notification"]

            case .ack, .hello, .inboxRequest, .approvalResponse, .clarificationResponse, .elicitationResponse, .logout:
                // These payloads don't carry a user-facing alert (most are
                // client→agent or terminal messages).  Show a generic card.
                showGeneric("unknown")
                return
            }

            contentHandler(bestAttempt)
        } catch {
            // Never expose the failure cause in the user-visible body — per
            // crypto.md §12.  Log the category for debugging.
            log.error("decrypt failed: \(String(describing: error), privacy: .public)")
            showGeneric("error")
        }
    }

    override func serviceExtensionTimeWillExpire() {
        // OS is about to terminate the extension.  The happy path in
        // `didReceive` calls `contentHandler` synchronously, so this is a
        // safety net: if we ever run out of time, the system will fall back
        // to delivering the original (undecrypted) push content, which
        // carries a generic `aps.alert`.  Nothing to do here.
    }
}
