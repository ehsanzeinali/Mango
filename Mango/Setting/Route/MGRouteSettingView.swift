import SwiftUI

struct MGRouteSettingView: View {
    
    @ObservedObject private var routeViewModel: MGConfigurationPersistentViewModel<MGConfiguration.Route>

    @State private var isAddRulePresented: Bool = false
    
    init(routeViewModel: MGConfigurationPersistentViewModel<MGConfiguration.Route>) {
        self._routeViewModel = ObservedObject(initialValue: routeViewModel)
    }
    
    var body: some View {
        Form {
            Section {
                Picker("Strategy", selection: $routeViewModel.model.domainStrategy) {
                    ForEach(MGConfiguration.Route.DomainStrategy.allCases) { strategy in
                        Text(strategy.description)
                    }
                }
            }
            Section {
                Picker("Matcher", selection: $routeViewModel.model.domainMatcher) {
                    ForEach(MGConfiguration.Route.DomainMatcher.allCases) { strategy in
                        Text(strategy.description)
                    }
                }
            }
            Section {
                ForEach($routeViewModel.model.rules) { rule in
                    MGPresentedButton {
                        MGRouteRuleSettingView(rule: rule.wrappedValue) { value in
                            rule.wrappedValue = value
                        }
                    } label: {
                        HStack {
                            LabeledContent {
                                Text(rule.outboundTag.wrappedValue.description)
                            } label: {
                                HStack {
                                    Image(systemName: "circle.fill")
                                        .resizable()
                                        .frame(width: 8, height: 8)
                                        .foregroundColor(rule.__enabled__.wrappedValue ? .green : .red.opacity(0.5))
                                    Text(rule.__name__.wrappedValue)
                                        .foregroundColor(.primary)
                                }
                            }
                        }
                    }
                }
                .onMove { from, to in
                    routeViewModel.model.rules.move(fromOffsets: from, toOffset: to)
                }
                .onDelete { offsets in
                    routeViewModel.model.rules.remove(atOffsets: offsets)
                }
            } header: {
                HStack {
                    Text("Rules")
                    Spacer()
                    Button("Add") {
                        isAddRulePresented.toggle()
                    }
                    .buttonStyle(.plain)
                    .font(.callout)
                    .foregroundColor(.accentColor)
                }
            }
        }
        .onDisappear {
            self.routeViewModel.save()
        }
        .lineLimit(1)
        .navigationTitle(Text("Route"))
        .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .environment(\.editMode, .constant(.active))
        .sheet(isPresented: $isAddRulePresented) {
            MGRouteRuleSettingView(rule: MGConfiguration.Route.Rule()) { value in
                routeViewModel.model.rules.append(value)
            }
        }
    }
}

struct MGRouteRuleSettingView: View {
    
    @Environment(\.dismiss) private var dismiss
    
    @State private var rule: MGConfiguration.Route.Rule
    
    private let onSave: (MGConfiguration.Route.Rule) -> Void
    
    init(rule: MGConfiguration.Route.Rule, onSave: @escaping (MGConfiguration.Route.Rule) -> Void) {
        self._rule = State(initialValue: rule)
        self.onSave = onSave
    }
    
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Name") {
                        TextField("", text: $rule.__name__)
                            .onSubmit {
                                if rule.__name__.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                    rule.__name__ = rule.__defaultName__
                                }
                            }
                    }
                }
                Section {
                    Toggle("Enabled", isOn: $rule.__enabled__)
                }
                Section {
                    Picker("Matcher", selection: $rule.domainMatcher) {
                        ForEach(MGConfiguration.Route.DomainMatcher.allCases) { strategy in
                            Text(strategy.description)
                        }
                    }
                }
                Group {
                    Section {
                        MGStringListEditor(strings: Binding(get: {
                            rule.domain ?? []
                        }, set: { newValue in
                            rule.domain = newValue.isEmpty ? nil : newValue
                        }), placeholder: nil)
                    } header: {
                        Text("Domain")
                    }
                    Section {
                        MGStringListEditor(strings: Binding(get: {
                            rule.ip ?? []
                        }, set: { newValue in
                            rule.ip = newValue.isEmpty ? nil : newValue
                        }), placeholder: nil)
                    } header: {
                        Text("IP")
                    }
                    Section {
                        MGStringListEditor(strings:  Binding {
                            let reval = rule.port ?? ""
                            return reval.components(separatedBy: ",").filter { !$0.isEmpty }
                        } set: { newValue in
                            let reval = newValue.joined(separator: ",")
                            rule.port = reval.isEmpty ? nil : reval
                        }, placeholder: nil)
                    } header: {
                        Text("Port")
                    }
                    Section {
                        MGStringListEditor(strings:  Binding {
                            let reval = rule.sourcePort ?? ""
                            return reval.components(separatedBy: ",").filter { !$0.isEmpty }
                        } set: { newValue in
                            let reval = newValue.joined(separator: ",")
                            rule.sourcePort = reval.isEmpty ? nil : reval
                        }, placeholder: nil)
                    } header: {
                        Text("Source Port")
                    }
                }
                Group {
                    Section {
                        HStack {
                            ForEach(MGConfiguration.Route.Network.allCases) { network in
                                MGToggleButton(title: network.description, isOn: Binding(get: {
                                    return rule.network.flatMap { $0.contains(network) } ?? false
                                }, set: { value in
                                    var reval = rule.network ?? []
                                    if value {
                                        reval.insert(network)
                                    } else {
                                        reval.remove(network)
                                    }
                                    rule.network = reval.isEmpty ? nil : reval
                                }))
                            }
                        }
                        .padding(.vertical, 4)
                    } header: {
                        Text("Network")
                    }
                    Section {
                        HStack {
                            ForEach(MGConfiguration.Route.Protocol_.allCases) { protocol_ in
                                MGToggleButton(title: protocol_.description, isOn: Binding(get: {
                                    return rule.protocol.flatMap { $0.contains(protocol_) } ?? false
                                }, set: { value in
                                    var reval = rule.protocol ?? []
                                    if value {
                                        reval.insert(protocol_)
                                    } else {
                                        reval.remove(protocol_)
                                    }
                                    rule.protocol = reval.isEmpty ? nil : reval
                                }))
                            }
                        }
                        .padding(.vertical, 4)
                    } header: {
                        Text("Protocol")
                    }
                    Section {
                        HStack {
                            ForEach(MGConfiguration.Route.Inbound.allCases) { inbound in
                                MGToggleButton(title: inbound.description, isOn: Binding(get: {
                                    return rule.inboundTag.flatMap { $0.contains(inbound) } ?? false
                                }, set: { value in
                                    var reval = rule.inboundTag ?? []
                                    if value {
                                        reval.insert(inbound)
                                    } else {
                                        reval.remove(inbound)
                                    }
                                    rule.inboundTag = reval.isEmpty ? nil : reval
                                }))
                            }
                        }
                        .padding(.vertical, 4)
                    } header: {
                        Text("Inbound")
                    }
                }
                Section {
                    Picker("Outbound", selection: $rule.outboundTag) {
                        ForEach(MGConfiguration.Outbound.Tag.allCases) { tag in
                            Text(tag.description)
                        }
                    }
                }
            }
            .lineLimit(1)
            .multilineTextAlignment(.trailing)
            .environment(\.editMode, .constant(.active))
            .navigationTitle(Text("Rule"))
            .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Save") {
                    self.onSave(self.rule)
                    self.dismiss()
                }
                .fontWeight(.medium)
            }
        }
    }
}
