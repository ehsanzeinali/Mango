import SwiftUI

struct MGTransportView: View {
    
    @ObservedObject private var vm: MGConfigurationEditViewModel
    
    init(vm: MGConfigurationEditViewModel) {
        self._vm = ObservedObject(initialValue: vm)
    }
        
    var body: some View {
        Picker("Transport", selection: $vm.model.streamSettings.transport) {
            ForEach(MGConfiguration.Outbound.StreamSettings.Transport.allCases) { type in
                Text(type.description)
            }
        }
        switch vm.model.streamSettings.transport {
        case .tcp:
            EmptyView()
        case .kcp:
            LabeledContent("MTU") {
                TextField("", value: $vm.model.streamSettings.kcpSettings.mtu, format: .number)
            }
            LabeledContent("TTI") {
                TextField("", value: $vm.model.streamSettings.kcpSettings.tti, format: .number)
            }
            LabeledContent("Uplink Capacity") {
                TextField("", value: $vm.model.streamSettings.kcpSettings.uplinkCapacity, format: .number)
            }
            LabeledContent("Downlink Capacity") {
                TextField("", value: $vm.model.streamSettings.kcpSettings.downlinkCapacity, format: .number)
            }
            Toggle("Congestion", isOn: .constant(false))
            LabeledContent("Read Buffer Size") {
                TextField("", value: $vm.model.streamSettings.kcpSettings.readBufferSize, format: .number)
            }
            LabeledContent("Write Buffer Size") {
                TextField("", value: $vm.model.streamSettings.kcpSettings.writeBufferSize, format: .number)
            }
            Picker("Header Type", selection: $vm.model.streamSettings.kcpSettings.header.type) {
                ForEach(MGConfiguration.Outbound.StreamSettings.HeaderType.allCases) { type in
                    Text(type.description)
                }
            }
            LabeledContent("Seed") {
                TextField("", text: $vm.model.streamSettings.kcpSettings.seed)
            }
        case .ws:
            LabeledContent("Host") {
                TextField("", text: Binding(get: {
                    vm.model.streamSettings.wsSettings.headers["Host"] ?? ""
                }, set: { value in
                    vm.model.streamSettings.wsSettings.headers["Host"] = value.trimmingCharacters(in: .whitespacesAndNewlines)
                }))
            }
            LabeledContent("Path") {
                TextField("", text: $vm.model.streamSettings.wsSettings.path)
            }
        case .http:
            LabeledContent("Host") {
                TextField("", text: Binding(get: {
                    vm.model.streamSettings.httpSettings.host.first ?? ""
                }, set: { value in
                    vm.model.streamSettings.httpSettings.host = [value.trimmingCharacters(in: .whitespacesAndNewlines)]
                }))
            }
            LabeledContent("Path") {
                TextField("", text: $vm.model.streamSettings.httpSettings.path)
            }
        case .quic:
            Picker("Security", selection: $vm.model.streamSettings.quicSettings.security) {
                ForEach(MGConfiguration.Outbound.Encryption.quic) { encryption in
                    Text(encryption.description)
                }
            }
            LabeledContent("Key") {
                TextField("", text: $vm.model.streamSettings.quicSettings.key)
            }
            Picker("Header Type", selection: $vm.model.streamSettings.quicSettings.header.type) {
                ForEach(MGConfiguration.Outbound.StreamSettings.HeaderType.allCases) { type in
                    Text(type.description)
                }
            }
        case .grpc:
            LabeledContent("Service Name") {
                TextField("", text: $vm.model.streamSettings.grpcSettings.serviceName)
            }
            Toggle("Multi-Mode", isOn: $vm.model.streamSettings.grpcSettings.multiMode)
        }
    }
}
