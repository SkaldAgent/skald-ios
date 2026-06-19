# Skald — iOS Remote Control for Skald Agent

**Skald** is an iOS app that lets you approve/reject tool calls and respond to clarification requests from your Skald Agent — all while Skald runs behind NAT at home.

---

## Architecture (tl;dr)

```
Skald (home)  ←WSS→  Relay (cloud)  ←WSS→  iPhone
   (agent)       E2E encrypted       (client)
```

- **Binary protobuf transport (V2)**: messages encoded as protobuf `RelayFrame` over WebSocket, replacing V1's JSON-over-text. Supports presence detection (online/offline) and a live channel for route-or-fail inbox delivery.
- **End-to-end encryption**: X25519 + Ed25519 + HKDF-SHA256 + AES-256-GCM (CryptoKit).
- **Relay** is zero-trust: it routes opaque encrypted blobs and bridges APNs push — it never sees contents.
- **Pairing** via QR code (contains relay URL, public keys, pairing token).

## Targets

| Target | Bundle ID | Role |
|--------|-----------|------|
| **Skald** | `net.skaldagent.inbox` | UI, WebSocket, send responses, owns `send_counter` |
| **NotificationServiceExtension** | `net.skaldagent.inbox.notification-extension` | Decrypts push payloads, builds rich notifications. No network. |

## Tech Stack

- **iOS 18**, SwiftUI, MVVM
- **CryptoKit** — no external crypto dependencies
- **URLSessionWebSocketTask** — native WebSocket client
- **SwiftProtobuf** — protobuf serialization for V2 relay transport
- **APNs** + Notification Service Extension + `UNNotificationAction`
- **Keychain** (App Group) — shared seed & counters between app and NSE
- **AVFoundation** — QR scanning
- **Zero** other third-party dependencies

## Screens

1. **ScanView** — QR code scanner (no pairing saved)
2. **PairingView** — pairing progress / awaiting authorization
3. **InboxView** — pending approvals + clarifications ✅❌
   - Pull-to-refresh: pull down to send `inbox_request` to agent with 5s timeout
   - Auto-reconnect with exponential backoff (no manual button)
   - "Disconnected — retrying…" banner when offline
4. **RejectReasonView** — reason text when rejecting
5. **SettingsView** — connection status, logout

## Project Structure

```
Skald/
├── App/                        # SwiftUI App + AppDelegate
├── Core/
│   ├── Crypto/                 # CryptoConstants, KeyManager, CryptoEngine
│   ├── Net/                    # RelayClient (WebSocket), Proto/ (generated protobuf)
│   ├── Store/                  # KeychainStore (App Group)
│   └── Model/                  # Payloads, PairingQR (Codable)
├── Features/
│   ├── Scan/                   # QR scanning
│   ├── Pairing/                # Pairing flow
│   ├── Inbox/                  # Approvals, clarifications, reject
│   └── Settings/               # Settings & logout
└── Resources/                  # Assets, Info.plist, entitlements
```

## State Machine

```
not_paired  →  pairing  →  awaiting_authorization  →  connected / disconnected
```

## Deployment (CLI)

Build + install on a connected iPhone from the terminal:

```bash
# 1. Regenerate the Xcode project (after changing project.yml)
xcodegen generate

# 2. Build for the connected device (filter output to avoid log spam)
xcodebuild \
  -project Skald.xcodeproj \
  -scheme Skald \
  -destination 'platform=iOS' \
  -allowProvisioningUpdates \
  build 2>&1 | grep -E "(error:|warning:|BUILD|FAILED|SUCCEEDED)" || true

# 3. Find the built .app (it's under DerivedData with a hash)
APP_PATH=$(ls -td ~/Library/Developer/Xcode/DerivedData/Skald-*/Build/Products/Debug-iphoneos/Skald.app 2>/dev/null | head -1)
echo "$APP_PATH"

# 4. Install on iPhone via ios-deploy
ios-deploy --bundle "$APP_PATH"
```

**Prerequisites:** XcodeGen (`brew install xcodegen`), ios-deploy (`brew install ios-deploy`), iPhone connected via USB and unlocked.

> The device ID is auto-detected by `ios-deploy` — no need to hardcode it.

