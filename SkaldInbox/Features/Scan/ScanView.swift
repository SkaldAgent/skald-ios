//
//  ScanView.swift
//  Skald
//
//  QR scanner screen.  Hosts an AVCaptureSession via UIViewControllerRepresentable
//  and forwards decoded strings to the view-model.  On success it calls
//  `onScanned(qrData)` (provided by the parent — RootView uses it to drive
//  `appState.startPairing`).
//

import AVFoundation
import SwiftUI
import UIKit

struct ScanView: View {

    /// Called once a valid QR has been parsed.
    let onScanned: (PairingQRData) -> Void

    @StateObject private var viewModel = ScanViewModel()
    @State private var hasPushed = false

    var body: some View {
        ZStack {
            // The camera preview.  We don't gate it on `hasPushed` because we
            // want it to keep animating in the background after a successful
            // scan (the parent swaps the view to PairingView in the same tick).
            QRScannerRepresentable { result in
                handleRawResult(result)
            }
            .ignoresSafeArea()

            VStack {
                headerBar
                Spacer()
                if let err = viewModel.lastError {
                    errorBanner(err)
                }
            }
        }
        .navigationBarHidden(true)
        .onChange(of: viewModel.qrPayload) { _, newValue in
            guard let qr = newValue, !hasPushed else { return }
            hasPushed = true
            onScanned(qr)
        }
    }

    // MARK: - Subviews

    private var headerBar: some View {
        VStack(spacing: 8) {
            HStack {
                Image(systemName: "qrcode.viewfinder")
                    .font(.title)
                Text("Scan Skald QR")
                    .font(.headline)
            }
            .foregroundStyle(.white)
            .padding(.top, 12)

            Text("Open Skald on your desktop and show the pairing code to the camera.")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundStyle(.white.opacity(0.85))
                .padding(.horizontal, 32)
        }
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity)
        .background(.black.opacity(0.55))
    }

    private func errorBanner(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
            Text(message)
                .font(.footnote)
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color.red.opacity(0.9), in: RoundedRectangle(cornerRadius: 10))
        .padding(.horizontal, 16)
        .padding(.bottom, 24)
        .transition(.move(edge: .bottom).combined(with: .opacity))
    }

    // MARK: - Scan handling

    private func handleRawResult(_ result: String) {
        // Avoid re-processing the same string while the parent transitions.
        guard !hasPushed else { return }
        _ = viewModel.handleScanResult(result)
    }
}

// MARK: - QRScannerRepresentable

/// A `UIViewControllerRepresentable` that owns an `AVCaptureSession` and
/// reports `.qr` metadata objects to `onResult`.  One-shot — the session is
/// stopped after the first successful scan.
struct QRScannerRepresentable: UIViewControllerRepresentable {

    let onResult: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerController {
        let vc = QRScannerController()
        vc.onResult = onResult
        return vc
    }

    func updateUIViewController(_ uiViewController: QRScannerController, context: Context) {
        // Nothing to update — the session is self-contained.
    }
}

final class QRScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {

    /// Called on the main queue with the raw payload of the first detected QR.
    var onResult: ((String) -> Void)?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasReported = false
    private let sessionQueue = DispatchQueue(label: "net.skaldagent.inbox.QRScanner")

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureSession()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        sessionQueue.async { [weak self] in
            guard let self = self else { return }
            if !self.session.isRunning {
                self.session.startRunning()
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        sessionQueue.async { [weak self] in
            self?.session.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video) else {
            showNoCamera()
            return
        }
        do {
            let input = try AVCaptureDeviceInput(device: device)
            if session.canAddInput(input) { session.addInput(input) }
        } catch {
            showNoCamera()
            return
        }

        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) { session.addOutput(output) }
        output.setMetadataObjectsDelegate(self, queue: .main)
        // `.qr` is the only metadata type we care about.
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        self.previewLayer = preview
    }

    private func showNoCamera() {
        let label = UILabel()
        label.text = "Camera not available.\nEnter the payload manually."
        label.numberOfLines = 0
        label.textColor = .white
        label.textAlignment = .center
        label.font = .systemFont(ofSize: 16, weight: .medium)
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            label.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
        ])
    }

    // MARK: - AVCaptureMetadataOutputObjectsDelegate

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection)
    {
        guard !hasReported else { return }
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              obj.type == .qr,
              let payload = obj.stringValue
        else { return }

        hasReported = true
        // Stop the session — the user can pull-to-refresh to scan again.
        sessionQueue.async { [weak self] in
            self?.session.stopRunning()
        }
        onResult?(payload)
    }
}
