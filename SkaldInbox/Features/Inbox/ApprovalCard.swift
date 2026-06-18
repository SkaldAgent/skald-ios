//
//  ApprovalCard.swift
//  Skald
//
//  Card showing a pending approval with Approve / Reject buttons.
//

import SwiftUI

struct ApprovalCard: View {

    let item: ApprovalItem
    let onApprove: () -> Void
    let onReject: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header

            Text(item.summary)
                .font(.body)
                .foregroundStyle(.primary)

            if let args = item.arguments, !args.isEmpty {
                if item.tool_name == "execute_cmd", let command = args["command"] {
                    // Special case: show command in monospace box
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Command")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(command.displayValue)
                            .font(.system(.body, design: .monospaced))
                            .foregroundStyle(.primary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color(.systemGray6))
                            )
                    }
                } else {
                    // Generic: show arguments as key/value list
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(Array(args.keys.sorted()), id: \.self) { key in
                            if let value = args[key] {
                                HStack(alignment: .top, spacing: 8) {
                                    Text(key)
                                        .font(.caption.weight(.medium))
                                        .foregroundStyle(.secondary)
                                        .frame(minWidth: 60, alignment: .trailing)
                                    Text(value.displayValue)
                                        .font(.body)
                                        .foregroundStyle(.primary)
                                }
                            }
                        }
                    }
                    .padding(12)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color(.systemGray6))
                    )
                }
            }

            if let detail = item.detail, !detail.isEmpty {
                DisclosureGroup("Details") {
                    Text(detail)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                }
                .font(.footnote)
            }

            HStack(spacing: 12) {
                Button {
                    onApprove()
                } label: {
                    Label("Approve", systemImage: "checkmark.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)

                Button(role: .destructive) {
                    onReject()
                } label: {
                    Label("Reject", systemImage: "xmark.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
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
                Text(item.tool_name)
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
}
