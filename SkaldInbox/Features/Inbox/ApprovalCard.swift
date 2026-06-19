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
        VStack(alignment: .leading, spacing: 10) {
            header

            Text(item.summary)
                .font(.footnote)
                .foregroundStyle(.primary)

            if let args = item.arguments, !args.isEmpty {
                if item.tool_name == "execute_cmd", let command = args["command"] {
                    Text(command.displayValue)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(
                            RoundedRectangle(cornerRadius: 6)
                                .fill(Color(.systemGray6))
                        )
                } else {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Array(args.keys.sorted()), id: \.self) { key in
                            if let value = args[key] {
                                HStack(alignment: .top, spacing: 8) {
                                    Text(key)
                                        .font(.caption2.weight(.medium))
                                        .foregroundStyle(.secondary)
                                        .frame(minWidth: 52, alignment: .trailing)
                                    Text(value.displayValue)
                                        .font(.footnote)
                                        .foregroundStyle(.primary)
                                }
                            }
                        }
                    }
                    .padding(10)
                    .background(
                        RoundedRectangle(cornerRadius: 6)
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

            HStack(spacing: 8) {
                Button {
                    onApprove()
                } label: {
                    Label("Approve", systemImage: "checkmark.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.roundedRectangle(radius: 4))
                .tint(.green)
                .controlSize(.small)

                Button(role: .destructive) {
                    onReject()
                } label: {
                    Label("Reject", systemImage: "xmark.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .buttonBorderShape(.roundedRectangle(radius: 4))
                .controlSize(.small)
            }
            .padding(.top, 2)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 5)
                .fill(Color(.secondarySystemGroupedBackground))
        )
    }

    private var header: some View {
        HStack(alignment: .top) {
            Text(item.tool_name)
                .font(.footnote.weight(.semibold))
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
