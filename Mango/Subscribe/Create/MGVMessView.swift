import SwiftUI

struct MGVMessView: View {
    
    @ObservedObject private var vm: MGConfigurationEditViewModel
    
    init(vm: MGConfigurationEditViewModel) {
        self._vm = ObservedObject(initialValue: vm)
    }
    
    var body: some View {
        LabeledContent("Address") {
            TextField("", text: $vm.model.vmessSettings.address)
        }
        LabeledContent("Port") {
            TextField("", value: $vm.model.vmessSettings.port, format: .number)
        }
        LabeledContent("ID") {
            TextField("", text: $vm.model.vmessSettings.user.id)
        }
        LabeledContent("Alert ID") {
            TextField("", value: $vm.model.vmessSettings.user.alterId, format: .number)
        }
        Picker("Security", selection: $vm.model.vmessSettings.user.security) {
            ForEach(MGConfiguration.Outbound.Encryption.vmess) { encryption in
                Text(encryption.description)
            }
        }
    }
}
