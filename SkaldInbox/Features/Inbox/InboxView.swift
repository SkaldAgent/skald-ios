//
//  InboxView.swift
//  Skald
//
//  The "I'm paired" screen — pending approvals, pending clarifications, and
//  a connection-state banner.  Listens to `.skaldOpenReject` /
//  `.skaldOpenRespond` notifications from the AppDelegate and presents the
//  corresponding modals.
//

import SwiftUI

struct InboxView: View {

    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var vm: InboxViewModel

    @State private var pendingReject: ApprovalItem?
    @State private var pendingRespond: ClarificationItem?

    var body: some View {
        ZStack(alignment: .top) {
            contentList

            if vm.connectionState != .connected {
                disconnectionBanner
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .navigationTitle("Inbox")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    vm.connect()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .accessibilityLabel("Reconnect")
            }
            ToolbarItem(placement: .topBarLeading) {
                if vm.connectionState == .connected {
                    Button("Disconnect") {
                        vm.disconnect()
                    }
                }
            }
        }
        .sheet(item: $pendingReject) { item in
            RejectReasonView(
                item: item,
                onCancel: { pendingReject = nil },
                onSubmit: { reason in
                    let target = item
                    pendingReject = nil
                    await vm.reject(target, reason: reason)
                }
            )
        }
        .sheet(item: $pendingRespond) { item in
            ClarificationResponseSheet(
                item: item,
                onCancel: { pendingRespond = nil },
                onSubmit: { answer in
                    let target = item
                    pendingRespond = nil
                    await vm.answer(target, answer: answer)
                }
            )
        }
        .onReceive(NotificationCenter.default.publisher(for: Foundation.Notification.Name.skaldOpenReject)) { note in
            let rid = (note.userInfo?["request_id"] as? String) ?? ""
            if let item = vm.approvals.first(where: { $0.request_id == rid }) {
                pendingReject = item
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: Foundation.Notification.Name.skaldOpenRespond)) { note in
            let rid = (note.userInfo?["request_id"] as? String) ?? ""
            if let item = vm.clarifications.first(where: { $0.request_id == rid }) {
                pendingRespond = item
            }
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var contentList: some View {
        if vm.approvals.isEmpty && vm.clarifications.isEmpty {
            emptyState
        } else {
            List {
                if !vm.approvals.isEmpty {
                    Section("Pending approvals") {
                        ForEach(vm.approvals, id: \.request_id) { item in
                            ApprovalCard(
                                item: item,
                                onApprove: {
                                    Task { await vm.approve(item) }
                                },
                                onReject: {
                                    pendingReject = item
                                }
                            )
                            .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                            .listRowSeparator(.hidden)
                        }
                    }
                }
                if !vm.clarifications.isEmpty {
                    Section("Clarifications") {
                        ForEach(vm.clarifications, id: \.request_id) { item in
                            ClarificationCard(item: item) { answer in
                                Task { await vm.answer(item, answer: answer) }
                            }
                            .listRowInsets(EdgeInsets(top: 8, leading: 16, bottom: 8, trailing: 16))
                            .listRowSeparator(.hidden)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .animation(.default, value: vm.approvals.count)
            .animation(.default, value: vm.clarifications.count)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "tray")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Nothing to do")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("New requests from Skald will appear here.")
                .font(.footnote)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var disconnectionBanner: some View {
        HStack {
            ProgressView()
                .controlSize(.small)
            Text("Disconnected — retrying…")
                .font(.footnote.weight(.medium))
            Spacer()
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.9))
    }
}

// MARK: - Clarification response sheet (used when the user tapped RESPOND on a push)

private struct ClarificationResponseSheet: View {
    let item: ClarificationItem
    let onCancel: () -> Void
    let onSubmit: (String) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var answer: String = ""
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(item.question)
                        .font(.body)
                    if let ctx = item.context, !ctx.isEmpty {
                        DisclosureGroup("Context") {
                            Text(ctx)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text(item.agent_label)
                }
                Section("Your answer") {
                    TextField("Write here…", text: $answer, axis: .vertical)
                        .lineLimit(3...10)
                        .focused($focused)
                }
            }
            .navigationTitle("Reply")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onCancel(); dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") {
                        let text = answer
                        Task {
                            await onSubmit(text)
                            dismiss()
                        }
                    }
                    .disabled(answer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .onAppear { focused = true }
        }
    }
}
