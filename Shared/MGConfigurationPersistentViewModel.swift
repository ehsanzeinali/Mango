import Foundation

public final class MGConfigurationPersistentViewModel<Model: Codable & Equatable & MGConfigurationPersistentModel>: ObservableObject {
    
    @Published var model = Model.currentValue()
    
    public init() {}
    
    func save(updated: () -> Void = {}) {
        do {
            guard self.model != Model.currentValue() else {
                return
            }
            UserDefaults.shared.set(try JSONEncoder().encode(self.model), forKey: Model.storeKey)
            updated()
        } catch {
            fatalError(error.localizedDescription)
        }
    }
}
