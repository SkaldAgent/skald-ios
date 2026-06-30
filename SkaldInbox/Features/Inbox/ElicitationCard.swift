//
//  ElicitationCard.swift
//  Skald
//
//  Card for a pending MCP elicitation: an MCP server asked for input the LLM
//  must not see (e.g. an SSH password).  Renders a secure input field (or a
//  yes/no confirmation) and never logs the value.
//

import SwiftUI

struct ElicitationCard: View {

    let item: ElicitationItem
    /// Accept: `nil` for a confirmation, the typed value for an input prompt.
    let onAccept: (String?) -> Void
    let onDecline: () -> Void

    @State private var value: String = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header

            Text(item.message)
                .font(.footnote)
                .foregroundStyle(.primary)

            if item.is_confirmation {
                confirmationButtons
            } else {
                inputControls
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(.secondarySystemGroupedBackground))
        )
    }

    // MARK: - Subviews

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Label("Secret requested", systemImage: "lock.fill")
                    .font(.footnote.weight(.semibold))
                Text(item.server_name)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(relativeTime)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    @ViewBuilder
    private var inputControls: some View {
        VStack(alignment: .trailing, spacing: 6) {
            Group {
                if item.sensitive {
                    SecureField(item.field_name ?? "Value", text: $value)
                } else {
                    TextField(item.field_name ?? "Value", text: $value)
                }
            }
            .textFieldStyle(.roundedBorder)
            .font(.footnote)
            .focused($focused)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .submitLabel(.send)
            .onSubmit { submit() }

            HStack(spacing: 8) {
                Button(role: .cancel) {
                    onDecline()
                } label: {
                    Text("Decline")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)

                Button {
                    submit()
                } label: {
                    Label("Submit", systemImage: "lock.open.fill")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .disabled(value.isEmpty)
            }
        }
        .padding(.top, 2)
    }

    private var confirmationButtons: some View {
        HStack(spacing: 8) {
            Spacer()
            Button(role: .cancel) {
                onDecline()
            } label: {
                Text("Decline")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            Button {
                onAccept(nil)
            } label: {
                Label("Allow", systemImage: "checkmark")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
        }
        .padding(.top, 2)
    }

    private var relativeTime: String {
        let date = Date(timeIntervalSince1970: TimeInterval(item.created_at) / 1000.0)
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    private func submit() {
        guard !value.isEmpty else { return }
        onAccept(value)
        // Wipe the local copy of the secret immediately after handing it off.
        value = ""
        focused = false
    }
}
