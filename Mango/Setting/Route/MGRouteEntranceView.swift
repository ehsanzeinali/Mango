import SwiftUI

struct MGRouteEntranceView: View {
    
    @StateObject private var routeViewModel = MGConfigurationPersistentViewModel<MGConfiguration.Route>()
    
    var body: some View {
        NavigationLink {
            MGRouteSettingView(routeViewModel: routeViewModel)
        } label: {
            Label("Route", systemImage: "arrow.triangle.branch")
        }
    }
}
