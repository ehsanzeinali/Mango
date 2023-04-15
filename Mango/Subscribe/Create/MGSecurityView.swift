import SwiftUI

struct MGSecurityView: View {
    
    @ObservedObject private var vm: MGConfigurationEditViewModel
    
    init(vm: MGConfigurationEditViewModel) {
        self._vm = ObservedObject(initialValue: vm)
    }
    
    var body: some View {
        Picker("Security", selection: $vm.model.streamSettings.security) {
            ForEach(MGConfiguration.Outbound.StreamSettings.Security.allCases) { type in
                Text(type.description)
            }
        }
        switch vm.model.streamSettings.security {
        case .none:
            EmptyView()
        case .tls:
            LabeledContent("Server Name") {
                TextField("", text: $vm.model.streamSettings.tlsSettings.serverName)
            }
            LabeledContent("ALPN") {
                HStack {
                    ForEach(MGConfiguration.Outbound.StreamSettings.ALPN.allCases) { alpn in
                        MGToggleButton(
                            title: alpn.description,
                            isOn: Binding(
                                get: {
                                    vm.model.streamSettings.tlsSettings.alpn.contains(alpn)
                                },
                                set: { value in
                                    if value {
                                        vm.model.streamSettings.tlsSettings.alpn.insert(alpn)
                                    } else {
                                        vm.model.streamSettings.tlsSettings.alpn.remove(alpn)
                                    }
                                }
                            )
                        )
                    }
                }
            }
            LabeledContent("Fingerprint") {
                Picker("", selection: $vm.model.streamSettings.tlsSettings.fingerprint) {
                    ForEach(MGConfiguration.Outbound.StreamSettings.Fingerprint.allCases) { fingerprint in
                        Text(fingerprint.description)
                    }
                }
            }
            Toggle("Allow Insecure", isOn: $vm.model.streamSettings.tlsSettings.allowInsecure)
        case .reality:
            LabeledContent("Server Name") {
                TextField("", text: $vm.model.streamSettings.realitySettings.serverName)
            }
            LabeledContent("Fingerprint") {
                Picker("", selection: $vm.model.streamSettings.realitySettings.fingerprint) {
                    ForEach(MGConfiguration.Outbound.StreamSettings.Fingerprint.allCases) { fingerprint in
                        Text(fingerprint.description)
                    }
                }
            }
            LabeledContent("Public Key") {
                TextField("", text: $vm.model.streamSettings.realitySettings.publicKey)
            }
            LabeledContent("Short ID") {
                TextField("", text: $vm.model.streamSettings.realitySettings.shortId)
            }
            LabeledContent("SpiderX") {
                TextField("", text: $vm.model.streamSettings.realitySettings.spiderX)
            }
        }
    }
}
