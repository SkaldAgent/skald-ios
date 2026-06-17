//
//  ScanViewModel.swift
//  Skald
//
//  Pure parsing / validation of the QR string. The AVFoundation plumbing
//  lives in `ScanView` (UIViewControllerRepresentable).
//

import Foundation
import SwiftUI

@MainActor
final class ScanViewModel: ObservableObject {

    /// Last scan error (human-readable, suitable for a banner).
    @Published var lastError: String?

    /// Last successfully-decoded QR.  The View observes this and pushes the
    /// PairingView when it becomes non-nil.
    @Published var qrPayload: PairingQRData?

    /// Parse a raw scan result.  Returns the decoded QR data on success, or
    /// `nil` on failure (with `error` populated for the UI banner).
    func handleScanResult(_ result: String) -> PairingQRData? {
        // Strip any stray whitespace (some QR renderers add a newline).
        let trimmed = result.trimmingCharacters(in: .whitespacesAndNewlines)

        let data: PairingQRData
        do {
            data = try PairingQRData.from(scanResult: trimmed)
        } catch let err as SkaldError {
            lastError = String(localized: "Invalid QR: ") + (err.errorDescription ?? String(localized: "unknown error"))
            return nil
        } catch {
            lastError = String(localized: "Invalid QR")
            return nil
        }

        // Recompute namespace_id from agent_ed25519_pub and constant-time
        // compare with the value the QR claims.  Per the spec, the QR
        // embeds both — we trust the one we recompute.
        do {
            let ok = try data.verifyNamespaceId()
            if !ok {
                lastError = String(localized: "Invalid QR: namespace_id mismatch")
                return nil
            }
        } catch let err as SkaldError {
            lastError = String(localized: "Invalid QR: ") + (err.errorDescription ?? String(localized: "unknown error"))
            return nil
        } catch {
            lastError = String(localized: "Invalid QR")
            return nil
        }

        lastError = nil
        qrPayload = data
        return data
    }

    func clearError() {
        lastError = nil
    }
}
