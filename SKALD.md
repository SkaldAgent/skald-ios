# Skald — iOS Remote Control for Skald Agent

**Skald** is an iOS app that lets you approve/reject tool calls and respond to clarification requests from your [Skald Agent](https://github.com/dguiducci/personal-agent) — all while Skald runs behind NAT at home.

---

## Architecture (tl;dr)

```
Skald (home)  ←WSS→  Relay (cloud)  ←WSS→  iPhone
   (agent)       E2E encrypted       (client)
```

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
- **APNs** + Notification Service Extension + `UNNotificationAction`
- **Keychain** (App Group) — shared seed & counters between app and NSE
- **AVFoundation** — QR scanning
- **Zero** third-party dependencies

## Screens

1. **ScanView** — QR code scanner (no pairing saved)
2. **PairingView** — pairing progress / awaiting authorization
3. **InboxView** — pending approvals + clarifications ✅❌
4. **RejectReasonView** — reason text when rejecting
5. **SettingsView** — connection status, logout

## Project Structure

```
Skald/
├── App/                        # SwiftUI App + AppDelegate
├── Core/
│   ├── Crypto/                 # CryptoConstants, KeyManager, CryptoEngine
│   ├── Net/                    # RelayClient (WebSocket)
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

## Reference Specs

All technical specs live at `/Users/dguiducci/rust/personal-agent/data/ios-app/`:

| File | What |
|------|------|
| [index.md](https://github.com/dguiducci/personal-agent/blob/main/data/ios-app/index.md) | Architecture, threat model, encoding conventions |
| [crypto.md](https://github.com/dguiducci/personal-agent/blob/main/data/ios-app/crypto.md) | Cryptographic contract (normative) |
| [relay-protocol.md](https://github.com/dguiducci/personal-agent/blob/main/data/ios-app/relay-protocol.md) | WebSocket protocol frames |
| [payloads.md](https://github.com/dguiducci/personal-agent/blob/main/data/ios-app/payloads.md) | E2E encrypted payload schemas |
| [ios-app.md](https://github.com/dguiducci/personal-agent/blob/main/data/ios-app/ios-app.md) | Full iOS implementation guide |
| [test-vectors.md](https://github.com/dguiducci/personal-agent/blob/main/data/ios-app/test-vectors.md) | Crypto test vectors (interop) |

---

*Generated 2026-06-17 — concise reference for the Skald iOS project.*
