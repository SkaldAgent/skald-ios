<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/badge/iOS-18.0+-000000?style=flat&logo=apple&logoColor=white">
  <img alt="iOS 18.0+" src="https://img.shields.io/badge/iOS-18.0+-000000?style=flat&logo=apple&logoColor=white">
</picture>
<img alt="Swift 5.10" src="https://img.shields.io/badge/Swift-5.10-F05138?style=flat&logo=swift&logoColor=white">
<img alt="CryptoKit" src="https://img.shields.io/badge/crypto-CryptoKit-1E8CBE?style=flat">
<img alt="Dependencies" src="https://img.shields.io/badge/dependencies-SwiftProtobuf-44CC11?style=flat">
<img alt="MIT" src="https://img.shields.io/badge/license-MIT-744c9c?style=flat">

<p align="center">
  <img src="https://img.shields.io/badge/Download_on_the_App_Store-0D96F6?style=for-the-badge&logo=appstore&logoColor=white" alt="Download on the App Store"> <em>— coming soon</em>
</p>

<br>

<p align="center">
  <strong>Skald</strong> is an iOS remote control for your <a href="https://github.com/xavix-yo/skald">Skald Agent</a> — the AI assistant that runs at home.
</p>

<p align="center">
  Approve tool calls, respond to clarifications, and keep your agent moving —<br>
  all from your pocket, <strong>end-to-end encrypted</strong>, with zero data in the cloud.
</p>

<br>

---

## ✨ Features

- **📥 Remote Inbox** — See pending approvals and clarification requests in real time.
- **✅ Approve / ❌ Reject** — One tap to authorise tool calls. Add a reason when rejecting.
- **💬 Answer clarifications** — Type your response when your agent needs guidance.
- **🔔 Push notifications** — Rich notifications with inline Approve / Reject / Reply actions, even from the Lock Screen.
- **🔐 End-to-end encryption** — X25519 + Ed25519 + HKDF-SHA256 + AES-256-GCM. The relay never sees your data.
- **📷 QR code pairing** — Scan a code on your desktop to pair. One-tap, no accounts.
- **📡 Works behind NAT** — WebSocket relay bridges your agent at home to your phone. No port forwarding.
- **🟢 Agent presence** — Know when your agent is online. Presence detection via V2 WebSocket protocol.
- **📨 Live channel** — Inbox requests routed directly over the live WebSocket connection — no polling.
- **🔗 Pipe (relay proxy)** — TURN-style relayed byte-stream between client and agent: ephemeral X25519 ECDH for per-pipe PFS key, AES-256-GCM per-frame encryption over a dedicated `/v1/pipe` WebSocket.

<br>

---

## 🔒 How it works

```
         Your home                        Cloud (relay)                     Your pocket

+-----------------------+      +--------------------------+      +-----------------------+
|   Skald Agent         |      |   Relay Server           |      |   Skald iOS           |
|   (namespace owner)   |      |   (zero-trust)           |      |   (this app)          |
|                       |      |                          |      |                       |
| +------------------+  |      |  * Routes blobs          |      |  +------------------+ |
| | Plugin Relay     |<-+------+--* Bridges APNs push     |------+->| CryptoEngine     | |
| | E2E encrypts     |  |      |  * Does NOT decrypt      |      |  | E2E decrypts     | |
| +------------------+  |      +--------------------------+      |  +------------------+ |
+-----------------------+                                        +-----------------------+
```

**Skald** runs an open-source AI agent on your own machine. The **iOS app** connects to it through a lightweight **relay server** that the Skald project also operates.

The relay is **zero-trust by design**:
- All messages are encrypted *before leaving* your device using X25519 key agreement + AES-256-GCM.
- The relay only sees opaque encrypted blobs, public keys, and push tokens — **never the content**.
- Pairing is done **out-of-band via QR code**: your phone learns the agent's public key directly, with no third party.

> ⚠️ **What the relay can see**: public keys (identifiers, not tied to real identities), push tokens, IP addresses, and message timing/metadata. This is explicitly stated in the [privacy model](https://github.com/xavix-yo/skald/blob/main/data/ios-app/index.md#42-cosa-il-relay-pu%C3%B2-vedere-e-fare-limiti-dichiarati) — the relay is *content-confidential*, not *metadata-private*.

<br>

---

## 🚀 Quick start

### Requirements

- **iOS 18.0+** (iPhone, iPad)
- A running [Skald Agent](https://github.com/xavix-yo/skald) instance with the Relay plugin enabled
- A [Skald Relay Server](https://github.com/xavix-yo/skald) endpoint (public or self-hosted)

### First run

1. Open **Skald** on your desktop and go to **Settings → Remote Control → Pair new device**.
2. Tap **Scan Skald QR** on the iOS app and point the camera at the QR code on your desktop.
3. Wait for the desktop to confirm the pairing.
4. Done. Approvals and clarifications will start appearing in your **Inbox** tab.

### Building from source

```bash
git clone https://github.com/xavix-yo/skald-ios.git
cd skald-ios

# Generate the Xcode project
brew install xcodegen   # if you don't have it yet
xcodegen generate

# Open and build
open Skald.xcodeproj
```

Only one external dependency via Swift Package Manager — **SwiftProtobuf** for protobuf serialization. XcodeGen handles the project file. Hit **⌘B** and you're done.

<br>

---

## 🧱 Architecture (for developers)

### State machine

```
not_paired  →  pairing  →  awaiting_authorization  →  connected / disconnected
```

### Project structure

```
Skald/
├── App/                        # SwiftUI App + AppDelegate
│   ├── SkaldApp.swift          # @main, AppState, RootView, MainTabView
│   └── AppDelegate.swift       # APNs registration, notification actions
│
├── Core/
│   ├── Crypto/
│   │   ├── KeyManager.swift    # Seed generation, key derivation (Ed25519 + X25519)
│   │   ├── CryptoEngine.swift  # ECDH → HKDF → AES-256-GCM seal/open (multi-version framing)
│   │   ├── CryptoConstants.swift  # Domain constants, nonce direction, error types
│   │   └── PipeCrypto.swift    # Per-pipe HKDF key derivation, pipe-auth signing, signal framing
│   ├── Net/
│   │   ├── RelayClient.swift   # WebSocket client (binary WS + protobuf RelayFrame)
│   │   ├── PipeTypes.swift     # PipeSignal, PipeInvite/Accept/Reject, PipeChallenge/Auth
│   │   ├── PipeMsgPack.swift   # Minimal MsgPack encoder/decoder (named-map, rmp-serde compat)
│   │   ├── PipeConnection.swift  # /v1/pipe data plane: auth handshake + AES-256-GCM frames
│   │   └── Proto/              # Generated protobuf Swift types
│   │       └── skald/relay/v2/
│   │           └── relay_frame.pb.swift
│   ├── Session/
│   │   ├── SkaldSession.swift  # App-wide E2E client actor (reconnect loop, multicast streams)
│   │   └── SkaldSession+Pipe.swift  # Pipe control plane: openPipe, acceptPipe, signal routing
│   ├── Store/
│   │   └── KeychainStore.swift # App Group keychain via Security.framework
│   └── Model/
│       ├── PairingQR.swift     # QR code parsing + verification
│       └── Payloads.swift      # E2E message schemas (Codable)
│
├── Features/
│   ├── Scan/                   # QR scanner (AVFoundation)
│   ├── Pairing/                # Pairing flow (WS → challenge → persist)
│   ├── Inbox/                  # Approvals, clarifications, approve/reject/answer
│   └── Settings/               # Connection state, keys, logout
│
└── Resources/
    ├── Localizable.xcstrings   # EN + IT localizations
    ├── InfoPlist.xcstrings     # Localized privacy strings
    └── Skald.entitlements      # App Group, push, Keychain
```

### Cryptographic contract (in brief)

| Operation | Algorithm |
|-----------|-----------|
| Key agreement | X25519 ECDH |
| Identity | Ed25519 (signing) |
| Key derivation | HKDF-SHA256 (salt + info domain separation) |
| Encryption | AES-256-GCM |
| Nonce | Monotonic counter per direction (prevents replay) |
| AAD | Binds `from_pubkey` + `to_pubkey` + `namespace_id` |
| Plaintext framing V2 (messages) | `0x01` ‖ `comp(1B)` ‖ `payload(JSON)` |
| Plaintext framing V2 (pipe signals) | `0x02` ‖ `0x00` ‖ `MsgPack(PipeSignal)` — routed before decompression |
| Pipe key (per-pipe PFS) | Ephemeral X25519 ECDH → HKDF-SHA256(`salt="skald-pipe-v1"`, `info="pipe-aes-256-gcm"`) |
| Pipe nonce | `DIR(4B)` ‖ `counter(8B BE)`, counters start at 1, initiator/responder directions separate |
| Pipe AAD | `connection_id` (32 B) |

Full specs: [`data/ios-app/`](https://github.com/xavix-yo/skald/tree/main/data/ios-app) in the Skald Agent repo.

### Dependencies

**One external dependency** plus Apple frameworks:

| Framework/Dependency | Purpose |
|-----------|---------|
| `SwiftUI` | UI |
| `CryptoKit` | All cryptography (X25519, Ed25519, HKDF, AES-GCM) |
| `Foundation` | Codable, WebSocket, Keychain |
| `SwiftProtobuf` (external) | Protobuf serialization for relay transport (V2); crypto remains CryptoKit-native |
| `AVFoundation` | QR scanning |
| `UserNotifications` | Push registration, notification actions, NSE |
| `Security` | Keychain (via `SecItem*`) |
| `OSLog` | Logging |
| `UIKit` | UIPasteboard, UIDevice |

<br>

---

## 📜 License

MIT — see [LICENSE](LICENSE).

<br>
## 🔗 Related

- [**Skald**](https://github.com/xavix-yo/skald) — The open-source AI assistant that this app controls.
