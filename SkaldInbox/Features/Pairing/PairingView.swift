//
//  PairingView.swift
//  Skald
//
//  Shown while the `.pairing` WS is being opened (and, in `awaiting` mode,
//  while we wait for the agent to confirm the device).
//

import SwiftUI

struct PairingView: View {

    let qrData: PairingQRData
    let awaiting: Bool

    @EnvironmentObject private var appState: AppState
    @StateObject private var viewModel = PairingViewModel()

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "antenna.radiowaves.left.and.right.circle")
                .font(.system(size: 72))
                .foregroundStyle(.tint)

            Text(headerTitle)
                .font(.title2.weight(.semibold))
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)

            Text(viewModel.status)
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)

            if case .connecting = viewModel.state {
                ProgressView()
                    .controlSize(.large)
                    .padding(.top, 8)
            }

            if case .error(let msg) = viewModel.state {
                VStack(spacing: 12) {
                    Label(msg, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)

                    Button {
                        viewModel.performPairing(qrData: qrData)
                    } label: {
                        Label("Retry", systemImage: "arrow.clockwise")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .padding(.horizontal, 32)
                }
            }

            if case .awaitingConfirm = viewModel.state {
                ProgressView()
                    .controlSize(.regular)

                Button(role: .cancel) {
                    viewModel.cancel()
                    appState.cancelPairing()
                } label: {
                    Text("Cancel")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .padding(.horizontal, 32)
                .padding(.top, 12)
            }

            Spacer()
        }
        .navigationTitle("Pairing")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            viewModel.attach(appState: appState)
            if !awaiting {
                viewModel.performPairing(qrData: qrData)
            }
        }
    }

    private var headerTitle: String {
        if awaiting { return "Awaiting confirmation" }
        if case .error = viewModel.state { return "Pairing error" }
        return "Connecting to Skald…"
    }
}
