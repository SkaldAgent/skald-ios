//
//  ClarificationCard.swift
//  Skald
//
//  Card showing a pending clarification with a text field + send button.
//

import SwiftUI

struct ClarificationCard: View {

    let item: ClarificationItem
    let onSend: (String) -> Void

    @State private var answer: String = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header

            Text(item.question)
                .font(.body)
                .foregroundStyle(.primary)

            if let ctx = item.context, !ctx.isEmpty {
                DisclosureGroup("Context") {
                    Text(ctx)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                }
                .font(.footnote)
            }

            VStack(alignment: .trailing, spacing: 8) {
                TextField("Write here…", text: $answer, axis: .vertical)
                    .lineLimit(2...6)
                    .focused($focused)
                    .textFieldStyle(.roundedBorder)
                    .submitLabel(.send)
                    .onSubmit { send() }

                Button {
                    send()
                } label: {
                    Label("Send", systemImage: "paperplane.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(answer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.top, 4)
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(.secondarySystemGroupedBackground))
        )
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Label("Clarification", systemImage: "questionmark.bubble")
                    .font(.headline)
                Text(item.agent_label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(relativeTime)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    private var relativeTime: String {
        let date = Date(timeIntervalSince1970: TimeInterval(item.created_at) / 1000.0)
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    private func send() {
        let text = answer.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        onSend(text)
        answer = ""
        focused = false
    }
}
