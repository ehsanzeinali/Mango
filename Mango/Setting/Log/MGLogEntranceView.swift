import SwiftUI

struct MGLogEntranceView: View {
        
    @StateObject private var logViewModel = MGConfigurationPersistentViewModel<MGConfiguration.Log>()
    
    var body: some View {
        NavigationLink {
            MGLogSettingView(logViewModel: logViewModel)
        } label: {
            Label("Log", systemImage: "doc.text.below.ecg")
        }
    }
}
