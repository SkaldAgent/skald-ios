//
//  RejectReasonView.swift
//  Skald
//
//  Modal that asks the user for a reason when they reject an approval.
//

import SwiftUI

struct RejectReasonView: View {

    let item: ApprovalItem
    let onCancel: () -> Void
    let onSubmit: (String) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var reason: String = ""
    @State private var sending = false
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(item.tool_name)
                        .font(.headline)
                    Text(item.summary)
                        .font(.body)
                } header: {
                    Text("Request from Skald")
                }

                Section {
                    TextField("Reason for rejection…", text: $reason, axis: .vertical)
                        .lineLimit(3...10)
                        .focused($focused)
                } header: {
                    Text("Why reject?")
                } footer: {
                    Text("The reason will be shown to Skald. You can leave it empty.")
                        .font(.caption)
                }
            }
            .navigationTitle("Reject")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        onCancel()
                        dismiss()
                    }
                    .disabled(sending)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(role: .destructive) {
                        let text = reason
                        sending = true
                        Task {
                            await onSubmit(text)
                            dismiss()
                        }
                    } label: {
                        if sending {
                            ProgressView()
                        } else {
                            Text("Reject")
                        }
                    }
                    .disabled(sending)
                }
            }
            .onAppear { focused = true }
        }
    }
}
