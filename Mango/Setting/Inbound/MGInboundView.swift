import SwiftUI

struct MGInboundView: View {
        
    @ObservedObject private var inboundViewModel: MGConfigurationPersistentViewModel<MGConfiguration.Inbound>
    
    init(inboundViewModel: MGConfigurationPersistentViewModel<MGConfiguration.Inbound>) {
        self._inboundViewModel = ObservedObject(initialValue: inboundViewModel)
    }
    
    var body: some View {
        Form {
            Section {
                LabeledContent("Listen", value: "[::1]")
                LabeledContent("Port") {
                    TextField("", text: Binding(get: {
                        "\(inboundViewModel.model.port)"
                    }, set: { value in
                        if let int = Int(value) {
                            inboundViewModel.model.port = int
                        } else {
                            inboundViewModel.model.port = 0
                        }
                    }))
                    .multilineTextAlignment(.trailing)
                    .keyboardType(.numberPad)
                }
            } header: {
                Text("SOSCK5")
            }
            Section {
                Toggle("Enabled", isOn: $inboundViewModel.model.sniffing.enabled)
                MGDisclosureGroup {
                    HStack {
                        ForEach(MGConfiguration.Inbound.DestinationOverride.allCases, id: \.rawValue) { `override` in
                            MGToggleButton(title: `override`.description, isOn: Binding(get: {
                                inboundViewModel.model.sniffing.destOverride.contains(`override`)
                            }, set: { value in
                                if value {
                                    inboundViewModel.model.sniffing.destOverride.insert(`override`)
                                } else {
                                    inboundViewModel.model.sniffing.destOverride.remove(`override`)
                                }
                            }))
                        }
                    }
                    .padding(.vertical, 4)
                } label: {
                    Text("Destination Override")
                }
                MGDisclosureGroup {
                    MGStringListEditor(strings: $inboundViewModel.model.sniffing.excludedDomains, placeholder: nil)
                        .moveDisabled(true)
                } label: {
                    LabeledContent("Excluded Domains", value: "\(inboundViewModel.model.sniffing.excludedDomains.count)")
                }
                Toggle("Metadata Only", isOn: $inboundViewModel.model.sniffing.metadataOnly)
                Toggle("Route Only", isOn: $inboundViewModel.model.sniffing.routeOnly)
            } header: {
                Text("Sniffing")
            }
        }
        .onDisappear {
            inboundViewModel.save()
        }
        .navigationTitle(Text("Inbound"))
        .environment(\.editMode, .constant(.active))
        .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
        .navigationBarTitleDisplayMode(.large)
    }
}
