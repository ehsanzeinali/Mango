import SwiftUI

struct MGAssetEntranceView: View {
    
    @StateObject private var assetViewModel = MGAssetViewModel()
    
    var body: some View {
        NavigationLink {
            MGAssetView(assetViewModel: assetViewModel)
        } label: {
            Label("Asset", systemImage: "folder")
        }
        .onAppear {
            assetViewModel.reload()
        }
    }
}
