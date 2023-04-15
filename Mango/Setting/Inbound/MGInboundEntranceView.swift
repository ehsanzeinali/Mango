import SwiftUI

struct MGInboundEntranceView: View {
        
    @StateObject private var inboundViewModel = MGConfigurationPersistentViewModel<MGConfiguration.Inbound>()
    
    var body: some View {
        NavigationLink {
            MGInboundView(inboundViewModel: inboundViewModel)
        } label: {
            Label("Inbound", systemImage: "square.and.arrow.down")
        }
    }
}
