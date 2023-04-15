import SwiftUI

struct MGTrojanView: View {
    
    @ObservedObject private var vm: MGConfigurationEditViewModel
    
    init(vm: MGConfigurationEditViewModel) {
        self._vm = ObservedObject(initialValue: vm)
    }
    
    var body: some View {
        LabeledContent("Address") {
            TextField("", text: $vm.model.trojanSettings.address)
        }
        LabeledContent("Port") {
            TextField("", value: $vm.model.trojanSettings.port, format: .number)
        }
        LabeledContent("Password") {
            TextField("", text: $vm.model.trojanSettings.password)
        }
        LabeledContent("Email") {
            TextField("", text: $vm.model.trojanSettings.email)
        }
    }
}
