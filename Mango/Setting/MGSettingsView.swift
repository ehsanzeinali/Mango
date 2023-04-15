import SwiftUI

struct MGSettingsView: View {
            
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    MGNetworkEntranceView()
                } header: {
                    Text("system")
                }
                Section {
                    MGLogEntranceView()
                    MGDNSEntranceView()
                    MGRouteEntranceView()
                    MGInboundEntranceView()
                    MGOutboundEntranceView()
                    MGAssetEntranceView()
                } header: {
                    Text("kernel")
                }
                Section {
                    LabeledContent {
                        Text(Bundle.appVersion)
                            .monospacedDigit()
                    } label: {
                        Label("application", systemImage: "app")
                    }
                    LabeledContent {
                        Text("1.8.0")
                            .monospacedDigit()
                    } label: {
                        Label("kernel", systemImage: "app.fill")
                    }
                } header: {
                    Text("Version")
                }
                Section {
                    MGVPNResettingView()
                }
            }
            .navigationTitle(Text("Setup"))
            .navigationBarTitleDisplayMode(.large)
        }
    }
}
