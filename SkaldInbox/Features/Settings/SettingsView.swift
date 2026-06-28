//
//  SettingsView.swift
//  Skald
//
//  Form-based settings: connection state, namespace, device, logout, about.
//

import SwiftUI
import UIKit

struct SettingsView: View {

    @EnvironmentObject private var appState: AppState
    @StateObject private var vm = SettingsViewModel()

    @State private var showLogoutConfirm = false
    @State private var copiedNamespace = false

    var body: some View {
        Form {
            statusSection
            namespaceSection
            connectedDevicesSection
            deviceSection
            logoutSection
            aboutSection
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            vm.attach(appState: appState)
        }
        .onChange(of: appState.phase) { _, _ in
            vm.refresh()
        }
        .confirmationDialog(
            "Confirm logout?",
            isPresented: $showLogoutConfirm,
            titleVisibility: .visible
        ) {
            Button("Logout", role: .destructive) {
                Task { await vm.logout() }
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Pairing credentials will be removed. You will need to scan the QR again.")
        }
    }

    // MARK: - Sections

    private var statusSection: some View {
        Section("Status") {
            HStack {
                Text("Connection")
                Spacer()
                statusBadge
            }
            HStack {
                Text("Phase")
                Spacer()
                Text(phaseLabel)
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        let (text, color): (String, Color) = {
            switch appState.phase {
            case .connected:    return ("Connected", .green)
            case .disconnected: return ("Disconnected", .orange)
            case .awaitingAuth: return ("Awaiting", .blue)
            case .pairing:      return ("Pairing…", .blue)
            case .notPaired:    return ("Not paired", .gray)
            }
        }()
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(text)
                .foregroundStyle(.secondary)
        }
    }

    private var phaseLabel: String {
        switch appState.phase {
        case .notPaired:            return "—"
        case .pairing:              return "Pairing in progress"
        case .awaitingAuth:         return "Awaiting confirmation"
        case .connected:            return "Connected"
        case .disconnected:         return "Disconnected"
        }
    }

    private var namespaceSection: some View {
        Section {
            Button {
                UIPasteboard.general.string = vm.namespaceIdHex
                copiedNamespace = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    copiedNamespace = false
                }
            } label: {
                HStack {
                    Text("Namespace ID")
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(copiedNamespace ? "Copied!" : vm.shortNamespace)
                        .font(.footnote.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        } header: {
            Text("Namespace")
        } footer: {
            Text("Tap to copy the full identifier.")
                .font(.caption)
        }
    }

    private var connectedDevicesSection: some View {
        Section {
            if vm.devices.isEmpty {
                Text("Not connected")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(vm.devices) { device in
                    deviceRow(device)
                }
            }
        } header: {
            Text("Connected Devices")
        } footer: {
            Text("Devices currently connected to the relay in your namespace.")
                .font(.caption)
        }
    }

    @ViewBuilder
    private func deviceRow(_ device: SettingsViewModel.RosterDevice) -> some View {
        HStack(spacing: 10) {
            Circle()
                .fill(.green)
                .frame(width: 8, height: 8)
            Text(device.label)
            Spacer()
            Text(device.fingerprint)
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }

    private var deviceSection: some View {
        Section("Device") {
            HStack {
                Text("My key (Ed25519)")
                Spacer()
                Text(vm.myEd25519PubTruncated)
                    .font(.footnote.monospaced())
                    .foregroundStyle(.secondary)
            }
            HStack {
                Text("Skald key (Ed25519)")
                Spacer()
                Text(vm.agentEd25519PubTruncated)
                    .font(.footnote.monospaced())
                    .foregroundStyle(.secondary)
            }
            HStack {
                Text("Name")
                Spacer()
                Text(vm.deviceName)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var logoutSection: some View {
        Section {
            Button(role: .destructive) {
                showLogoutConfirm = true
            } label: {
                if vm.isLoggingOut {
                    HStack {
                        ProgressView()
                            .controlSize(.small)
                        Text("Disconnecting…")
                    }
                } else {
                    Text("Logout")
                }
            }
            .disabled(vm.isLoggingOut)
        } footer: {
            Text("Clears pairing credentials from this device. The Skald desktop will need to authorize this device again.")
                .font(.caption)
        }
    }

    private var aboutSection: some View {
        Section("About") {
            HStack {
                Text("Version")
                Spacer()
                Text(vm.appVersion)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private extension SettingsViewModel {
    var shortNamespace: String {
        guard namespaceIdHex.count > 12 else { return namespaceIdHex }
        let head = namespaceIdHex.prefix(8)
        let tail = namespaceIdHex.suffix(8)
        return "\(head)…\(tail)"
    }
}
