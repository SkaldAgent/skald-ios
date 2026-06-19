//
//  PairedIdentity.swift
//  Skald
//
//  An immutable snapshot of the paired identity, read once from the App-Group
//  Keychain.  This centralises what used to be **duplicated in four places**
//  (InboxViewModel, SettingsViewModel, PairingViewModel and AppDelegate): the
//  `CryptoEngine` factory and the `RelayClient` construction from the stored
//  seed + agent pubkeys + relay URL.
//
//  App-only.  The NSE builds its `CryptoEngine` inline (its dependency surface
//  is tighter and it never opens a transport), so this type lives in the app
//  target only — see `SkaldSession`.
//

import Foundation

/// Everything needed to build a `CryptoEngine` and a `RelayClient` for the
/// agent peer.  Load it once with `PairedIdentity.load()`; treat it as an
/// immutable value for the lifetime of one operation (it does NOT observe
/// later Keychain mutations).
struct PairedIdentity {

    let relayURL: URL
    /// 64-char lowercase hex of `namespace_id` (crypto.md §7).
    let namespaceIdHex: String
    /// 32B raw `namespace_id`.
    let namespaceIdRaw: Data
    /// Our derived keypair (re-derived from the seed; never persisted).
    let keypair: SkaldKeypair
    /// Raw 32B Ed25519 / X25519 public keys for *us* (the client).
    let myEd25519Pub: Data
    let myX25519Pub: Data
    /// Raw 32B Ed25519 / X25519 public keys for the *agent* (the peer).
    let agentEd25519Pub: Data
    let agentX25519Pub: Data
    /// Hex APNs device token, if registered.  `nil` before first registration.
    let deviceTokenHex: String?

    // MARK: - Load

    /// Read the paired identity from the App-Group Keychain.
    ///
    /// Throws `SkaldError.invalidPayload` if any required field is missing or
    /// malformed — i.e. we are not paired.  `loadOrCreateSeed`/`deriveKeys`
    /// throw their own `SkaldError` on a genuine crypto failure.
    static func load() throws -> PairedIdentity {
        let store = KeychainStore.shared

        let seed = try KeyManager.shared.loadOrCreateSeed()
        let keypair = try KeyManager.shared.deriveKeys(seed: seed)

        guard let relayString = try store.getString(for: KeychainStore.Key.relayUrl),
              let relayURL = URL(string: relayString)
        else {
            throw SkaldError.invalidPayload
        }

        let agentEd = try require32(store, KeychainStore.Key.agentEd25519Pub)
        let agentX  = try require32(store, KeychainStore.Key.agentX25519Pub)
        let nsRaw   = try require32(store, KeychainStore.Key.namespaceId)
        let deviceToken = (try? store.getString(for: KeychainStore.Key.deviceToken)) ?? nil

        return PairedIdentity(
            relayURL: relayURL,
            namespaceIdHex: Hex.encode(nsRaw),
            namespaceIdRaw: nsRaw,
            keypair: keypair,
            myEd25519Pub: keypair.signing.publicKey.rawRepresentation,
            myX25519Pub: keypair.agreement.publicKey.rawRepresentation,
            agentEd25519Pub: agentEd,
            agentX25519Pub: agentX,
            deviceTokenHex: deviceToken
        )
    }

    // MARK: - Factories

    /// Build the `CryptoEngine` for the agent peer (we send to the agent and
    /// receive from the agent).
    func makeEngine() -> CryptoEngine {
        CryptoEngine(
            agentX25519Pub: agentX25519Pub,
            agentEd25519Pub: agentEd25519Pub,
            myX25519Priv: keypair.agreement,
            myEd25519Pub: myEd25519Pub,
            namespaceIdRaw: namespaceIdRaw
        )
    }

    /// Build a `.client`-role transport for a (long-lived or one-shot) session.
    func makeClientTransport() -> RelayClient {
        RelayClient(
            relayURL: relayURL,
            role: .client,
            namespaceIdHex: namespaceIdHex,
            pairingTokenHex: nil,
            clientEd25519Pub: Hex.encode(myEd25519Pub),
            clientX25519Pub: Hex.encode(myX25519Pub),
            deviceToken: deviceTokenHex
        )
    }

    // MARK: - Helpers

    /// Read a required 32-byte Keychain entry, mapping any failure (missing,
    /// wrong length, OSStatus) to `SkaldError.invalidPayload`.
    private static func require32(_ store: KeychainStore, _ account: String) throws -> Data {
        do {
            guard let d = try store.getData(for: account), d.count == 32 else {
                throw SkaldError.invalidPayload
            }
            return d
        } catch let e as SkaldError {
            throw e
        } catch {
            throw SkaldError.invalidPayload
        }
    }
}
