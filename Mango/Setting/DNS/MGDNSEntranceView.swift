import SwiftUI

struct MGDNSEntranceView: View {
    
    @StateObject private var dnsViewModel = MGConfigurationPersistentViewModel<MGConfiguration.DNS>()
    
    var body: some View {
        NavigationLink {
            MGDNSSettingView(dnsViewModel: dnsViewModel)
        } label: {
            Label("DNS", systemImage: "network")
        }
    }
}
