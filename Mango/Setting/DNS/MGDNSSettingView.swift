import SwiftUI

struct MGDNSSettingView: View {
    
    @ObservedObject private var dnsViewModel: MGConfigurationPersistentViewModel<MGConfiguration.DNS>
    
    @State private var isAddHostPresented: Bool = false
    @State private var isAddServerPresented: Bool = false
    
    init(dnsViewModel: MGConfigurationPersistentViewModel<MGConfiguration.DNS>) {
        self._dnsViewModel = ObservedObject(initialValue: dnsViewModel)
    }
    
    var body: some View {
        Form {
            Section {
                ForEach(Binding(get: {
                    dnsViewModel.model.hosts ?? []
                }, set: { value in
                    dnsViewModel.model.hosts = value
                })) { host in
                    MGDNSHostItemView(host: host)
                }
                .onDelete { offsets in
                    dnsViewModel.model.hosts?.remove(atOffsets: offsets)
                }
            } header: {
                HStack {
                    Text("Hosts")
                    Spacer()
                    Button("Add") {
                        isAddHostPresented.toggle()
                    }
                    .buttonStyle(.plain)
                    .foregroundColor(.accentColor)
                }
            }
            Section {
                ForEach(Binding(get: {
                    dnsViewModel.model.servers ?? []
                }, set: { value in
                    dnsViewModel.model.servers = value
                })) { server in
                    MGDNSServerItemView(server: server)
                }
                .onMove { from, to in
                    dnsViewModel.model.servers?.move(fromOffsets: from, toOffset: to)
                }
                .onDelete { offsets in
                    dnsViewModel.model.servers?.remove(atOffsets: offsets)
                }
            } header: {
                HStack {
                    Text("Servers")
                    Spacer()
                    Button("Add") {
                        isAddServerPresented.toggle()
                    }
                    .buttonStyle(.plain)
                    .foregroundColor(.accentColor)
                }
            }
            Section {
                LabeledContent {
                    TextField("", text: Binding(get: {
                        dnsViewModel.model.clientIp ?? ""
                    }, set: { value in
                        let reval = value.trimmingCharacters(in: .whitespacesAndNewlines)
                        dnsViewModel.model.clientIp = reval.isEmpty ? nil : reval
                    }))
                } label: {
                    Text("Client IP")
                }
            }
            Section {
                LabeledContent {
                    Picker("Query Strategy", selection: $dnsViewModel.model.queryStrategy) {
                        ForEach(MGConfiguration.DNS.QueryStrategy.allCases) { strategy in
                            Text(strategy.description)
                        }
                    }
                    .labelsHidden()
                    .fixedSize()
                } label: {
                    Text("Query Strategy")
                }
            }
            Section {
                Toggle("Cache", isOn: $dnsViewModel.model.disableCache)
            }
            Section {
                Toggle("Fallback", isOn: $dnsViewModel.model.disableFallback)
            }
            Section {
                Toggle("Fallback If Match", isOn: $dnsViewModel.model.disableFallbackIfMatch)
            }
        }
        .lineLimit(1)
        .multilineTextAlignment(.trailing)
        .environment(\.editMode, .constant(.active))
        .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
        .navigationTitle(Text("DNS"))
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $isAddHostPresented) {
            MGDNSHostView(host: MGConfiguration.DNS.Host()) { value in
                if dnsViewModel.model.hosts == nil {
                    dnsViewModel.model.hosts = [value]
                } else {
                    dnsViewModel.model.hosts?.append(value)
                }
            }
        }
        .sheet(isPresented: $isAddServerPresented) {
            MGDNSServerView(server: MGConfiguration.DNS.Server()) { value in
                if dnsViewModel.model.servers == nil {
                    dnsViewModel.model.servers = [value]
                } else {
                    dnsViewModel.model.servers?.append(value)
                }
            }
        }
    }
}

struct MGDNSHostItemView: View {
    
    @Binding var host: MGConfiguration.DNS.Host
    
    @State private var isPresented: Bool = false
    
    var body: some View {
        HStack(spacing: 0) {
            Text(host.key)
            Spacer()
        }
        .contentShape(Rectangle())
        .onTapGesture {
            isPresented.toggle()
        }
        .sheet(isPresented: $isPresented) {
            MGDNSHostView(host: host) { value in
                host = value
            }
        }
    }
}

struct MGDNSHostView: View {
    
    @Environment(\.dismiss) private var dismiss
    
    @State private var host: MGConfiguration.DNS.Host
    
    private let onSave: (MGConfiguration.DNS.Host) -> Void
    
    init(host: MGConfiguration.DNS.Host, onSave: @escaping (MGConfiguration.DNS.Host) -> Void) {
        self._host = State(initialValue: host)
        self.onSave = onSave
    }
        
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("", text: $host.key)
                        .multilineTextAlignment(.leading)
                } header: {
                    Text("Key")
                }
                Section {
                    MGStringListEditor(strings: $host.values, placeholder: nil)
                        .moveDisabled(true)
                } header: {
                    Text("Values")
                }
            }
            .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
            .environment(\.editMode, .constant(.active))
            .navigationTitle("Host")
            .toolbar(.visible, for: .navigationBar)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Save") {
                    self.onSave(self.host)
                    self.dismiss()
                }
                .fontWeight(.medium)
            }
        }
    }
}

struct MGDNSServerItemView: View {
    
    @Binding var server: MGConfiguration.DNS.Server
    
    @State private var isPresented: Bool = false
    
    var body: some View {
        HStack(spacing: 0) {
            Text(server.address)
            Spacer()
        }
        .contentShape(Rectangle())
        .onTapGesture {
            isPresented.toggle()
        }
        .sheet(isPresented: $isPresented) {
            MGDNSServerView(server: self.server) { value in
                self.server = value
            }
        }
    }
}

struct MGDNSServerView: View {
    
    @Environment(\.dismiss) private var dismiss
    
    @State private var server: MGConfiguration.DNS.Server
    
    private let onSave: (MGConfiguration.DNS.Server) -> Void
    
    init(server: MGConfiguration.DNS.Server, onSave: @escaping (MGConfiguration.DNS.Server) -> Void) {
        self._server = State(initialValue: server)
        self.onSave = onSave
    }
        
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Address") {
                        TextField("", text: $server.address)
                    }
                }
                if server.__object__ {
                    Section {
                        LabeledContent("Port") {
                            TextField("", value: $server.port, format: .number)
                        }
                    }
                    Section {
                        MGStringListEditor(strings: $server.domains, placeholder: nil)
                    } header: {
                        Text("Domain")
                    }
                    Section {
                        MGStringListEditor(strings: $server.expectIPs, placeholder: nil)
                    } header: {
                        Text("Expect IP")
                    }
                    Section{
                        Toggle("Skip Fallback", isOn: $server.skipFallback)
                    }
                    Section {
                        LabeledContent("Client IP") {
                            TextField("", text: Binding(get: {
                                server.clientIP ?? ""
                            }, set: { newValue in
                                let reval = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
                                server.clientIP = reval.isEmpty ? nil : reval
                            }))
                        }
                    }
                }
                Section {
                    Button {
                        withAnimation {
                            server.__object__.toggle()
                        }
                    } label: {
                        HStack {
                            Spacer()
                            Text(server.__object__ ? "Less" : "More")
                            Spacer()
                        }
                    }
                }
            }
            .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
            .multilineTextAlignment(.trailing)
            .environment(\.editMode, .constant(.active))
            .navigationTitle(Text("Server"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Save") {
                    self.onSave(self.server)
                    self.dismiss()
                }
                .fontWeight(.medium)
            }
        }
    }
}
