import Foundation

final class MGNetworkViewModel: ObservableObject {
    
    @Published var hideVPNIcon: Bool
    @Published var ipv6Enabled: Bool
        
    init() {
        let model = MGNetworkModel.current
        self.hideVPNIcon = model.hideVPNIcon
        self.ipv6Enabled = model.ipv6Enabled
    }
    
    func save(updated: () -> Void) {
        do {
            let model = MGNetworkModel(
                hideVPNIcon: self.hideVPNIcon,
                ipv6Enabled: self.ipv6Enabled
            )
            guard model != MGNetworkModel.current else {
                return
            }
            UserDefaults.shared.set(try JSONEncoder().encode(model), forKey: MGConstant.network)
            updated()
        } catch {
            fatalError(error.localizedDescription)
        }
    }
}
