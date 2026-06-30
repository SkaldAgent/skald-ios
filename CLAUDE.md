# CLAUDE.md — Skald iOS

iOS client for the **Skald Agent**. Lets you approve/reject tool calls, answer
clarifications, and remote-control the agent while it runs behind NAT at home.
See [SKALD.md](SKALD.md) for the in-repo architecture summary.

```
Skald Agent (home)  ←WSS→  Relay (cloud)  ←WSS→  iPhone (this repo)
   ../skald            E2E encrypted, zero-trust    client
```

## Companion repo — the Skald Agent (`../skald/`)

The agent and all backend infrastructure live in the **`../skald/`** repo
(a sibling checkout, relative to this project's root), a Rust workspace.
Key locations:

| What | Path |
|------|------|
| **Architecture docs (start here)** | `../skald/docs/index.md` |
| **Relay server** (cloud, zero-trust byte router + APNs/push bridge) | `../skald/crates/skald-relay-server` |
| **Relay client** (Rust) | `../skald/crates/skald-relay-client` |
| **Relay shared types / pipe protocol** | `../skald/crates/skald-relay-common` (`src/pipe.rs`) |
| **Mobile connector** (agent-side bridge to the relay/app; handles pipe stream types) | `../skald/crates/plugin-mobile-connector` |
| **Audio: local STT** | `../skald/crates/plugin-transcribe-whisper-local` |
| **Audio: local TTS** | `../skald/crates/plugin-tts-kokoro`, `../skald/crates/plugin-tts-orpheus-3b` |
| **Audio abstractions (traits, model registry)** | `../skald/crates/core-api/src/transcribe.rs`, `../skald/crates/core-api/src/tts.rs` |

The pipe protocol (TURN-style relayed E2E byte stream) is implemented on both
sides: iOS in [SkaldInbox/Core/Net/](SkaldInbox/Core/Net/), Rust in the relay
crates above. A new feature stream is just a new `stream_type` (e.g. the Web tab
uses `"http-local-proxy"`).

## In-progress work

- **VoIP / voice call** — talk to the agent like a phone call (AirPods, phone in
  pocket). STT/TTS run on the **local Skald models** (whisper-local + kokoro/
  orpheus), not on-device. Rough plan: [todo/voip-project.md](todo/voip-project.md).
