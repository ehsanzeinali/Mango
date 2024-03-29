import SwiftUI

struct MGNetworkEntranceView: View {
        
    @StateObject private var networkViewModel = MGNetworkViewModel()
    
    var body: some View {
        NavigationLink {
            MGNetworkSettingView(networkViewModel: networkViewModel)
        } label: {
            LabeledContent {
                Text(content)
            } label: {
                Label("network settings", systemImage: "network")
            }
        }
    }
    
    private var content: String {
        var strings: [String] = []
        strings.append("IPv4")
        if networkViewModel.ipv6Enabled {
            strings.append("IPv6")
        }
        if strings.isEmpty {
            return "none"
        } else {
            return strings.joined(separator: " & ")
        }
    }
}
