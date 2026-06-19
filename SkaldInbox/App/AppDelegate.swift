//
//  AppDelegate.swift
//  Skald
//
//  Handles APNs registration, notification categories, and the action
//  callbacks (APPROVE / REJECT / RESPOND) for rich pushes.
//

import Foundation
import UIKit
import UserNotifications

// MARK: - Cross-scene notifications

extension Foundation.Notification.Name {
    /// Posted when the user taps REJECT on an approval push.  The active
    /// InboxView listens for this and presents `RejectReasonView` modally.
    static let skaldOpenReject = Foundation.Notification.Name("net.skaldagent.inbox.openReject")

    /// Posted when the user taps RESPOND on a clarification push.  The
    /// InboxView listens and scrolls to / focuses the matching item.
    static let skaldOpenRespond = Foundation.Notification.Name("net.skaldagent.inbox.openRespond")
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {

    /// Set by `SkaldApp.body.onAppear`.  We need this reference to
    /// store the device token and to inspect the current phase.
    var appState: AppState?

    // MARK: - App lifecycle

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions:
                     [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool
    {
        UNUserNotificationCenter.current().delegate = self
        Self.setNotificationCategories()

        // Request push permission up front.  We don't await the result — the
        // user can decline and the app still works (we just won't receive
        // background notifications).
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .badge, .sound]
        ) { granted, _ in
            if granted {
                DispatchQueue.main.async {
                    UIApplication.shared.registerForRemoteNotifications()
                }
            }
        }

        return true
    }

    // MARK: - APNs registration

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data)
    {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        // Persist immediately so the next cold launch can hand the token to the
        // relay on the very first connect (APNs registration is async and
        // normally completes *after* we've already opened the WS session).
        try? KeychainStore.shared.setString(hex, for: KeychainStore.Key.deviceToken)
        Task { @MainActor in
            guard let appState = self.appState else { return }
            let changed = appState.deviceTokenHex != hex
            appState.deviceTokenHex = hex
            // If the token arrived (or rotated) after we already authenticated,
            // the relay still has the old/empty token. Force a reconnect so the
            // client handshake re-sends the fresh token; otherwise pushes keep
            // failing with `MissingDeviceToken` until the next relaunch.
            if changed { appState.onDeviceTokenChanged?() }
        }
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error)
    {
        // Best-effort: log only.  We don't surface this to the user — the app
        // still works, the user just won't get background pushes.
        NSLog("Skald: APNs registration failed: \(error.localizedDescription)")
    }

    // MARK: - Notification categories

    private static func setNotificationCategories() {
        let approve = UNNotificationAction(
            identifier: "APPROVE",
            title: String(localized: "✅ Approve"),
            options: [.authenticationRequired]
        )
        let reject = UNNotificationAction(
            identifier: "REJECT",
            title: String(localized: "❌ Reject"),
            options: [.authenticationRequired, .destructive, .foreground]
        )
        let respond = UNNotificationAction(
            identifier: "RESPOND",
            title: String(localized: "✏️ Reply"),
            options: [.foreground]
        )
        let category = UNNotificationCategory(
            identifier: "skald_inbox",
            actions: [approve, reject, respond],
            intentIdentifiers: [],
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    // MARK: - UNUserNotificationCenterDelegate

    /// Show banners even when the app is in the foreground — the user opened
    /// the app specifically to handle Skald items, so being silent would be
    /// surprising.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                @escaping (UNNotificationPresentationOptions) -> Void)
    {
        completionHandler([.banner, .sound, .list])
    }

    /// Handle user actions on a delivered notification.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler:
                                @escaping () -> Void)
    {
        let userInfo = response.notification.request.content.userInfo
        let requestId = (userInfo["request_id"] as? String) ?? ""
        let kind      = (userInfo["kind"] as? String) ?? ""

        switch response.actionIdentifier {
        case "APPROVE":
            // Spawn a one-shot E2E send in the background.
            Task.detached(priority: .userInitiated) { [weak self] in
                await self?.sendOneShotApproval(requestId: requestId)
            }
            completionHandler()

        case "REJECT":
            // Bring the reject modal to the front; the user will type a
            // reason and we send `approval_response { decision:"rejected" }`
            // from the InboxViewModel.
            NotificationCenter.default.post(
                name: Foundation.Notification.Name.skaldOpenReject,
                object: nil,
                userInfo: ["request_id": requestId]
            )
            completionHandler()

        case "RESPOND":
            NotificationCenter.default.post(
                name: Foundation.Notification.Name.skaldOpenRespond,
                object: nil,
                userInfo: ["request_id": requestId]
            )
            completionHandler()

        default:
            // Default tap — no-op.  The InboxView will still show the item
            // when the user opens the app.
            completionHandler()
        }

        // `kind` is reserved for future per-kind routing (we only have
        // approvals + clarifications today, both with the same action set).
        _ = kind
    }

    // MARK: - One-shot approval send

    /// Open a short `.client` WS, send an `approval_response { approved }`, and
    /// close.  Runs in a detached Task so the system notification handler can
    /// return immediately.  `SkaldSession.sendOneShot` handles the transient
    /// connect/encrypt/send/close and gives up silently if we're not paired.
    private func sendOneShotApproval(requestId: String) async {
        guard !requestId.isEmpty else { return }
        let payload = ApprovalResponse(
            v: 1,
            kind: "approval_response",
            id: UUID().uuidString.lowercased(),
            ts: Int64(Date().timeIntervalSince1970 * 1000),
            request_id: requestId,
            decision: "approved",
            reason: nil
        )
        do {
            try await SkaldSession.sendOneShot(payload)
        } catch {
            NSLog("Skald: one-shot APPROVE failed: \(error.localizedDescription)")
        }
    }
}
