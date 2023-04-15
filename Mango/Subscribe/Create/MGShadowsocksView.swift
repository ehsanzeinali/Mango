import SwiftUI

struct MGShadowsocksView: View {
    
    @ObservedObject private var vm: MGConfigurationEditViewModel
    
    init(vm: MGConfigurationEditViewModel) {
        self._vm = ObservedObject(initialValue: vm)
    }
    
    var body: some View {
        LabeledContent("Address") {
            TextField("", text: $vm.model.shadowsocksSettings.address)
        }
        LabeledContent("Port") {
            TextField("", value: $vm.model.shadowsocksSettings.port, format: .number)
        }
        LabeledContent("Email") {
            TextField("", text: $vm.model.shadowsocksSettings.email)
        }
        LabeledContent("Password") {
            TextField("", text: $vm.model.shadowsocksSettings.password)
        }
        LabeledContent("Method") {
            Picker("Method", selection: $vm.model.shadowsocksSettings.method) {
                ForEach(MGConfiguration.Outbound.ShadowsocksSettings.Method.allCases) { method in
                    Text(method.description)
                }
            }
            .labelsHidden()
            .fixedSize()
        }
        Toggle("UOT", isOn: $vm.model.shadowsocksSettings.uot)
    }
}
