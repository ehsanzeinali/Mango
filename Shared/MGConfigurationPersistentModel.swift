import Foundation

public protocol MGConfigurationPersistentModel {
    
    static var storeKey:String {
        get
    }
    
    static var defaultValue: Self {
        get
    }
    
    static func currentValue() -> Self
}

public extension MGConfigurationPersistentModel where Self: Codable {
    
    static func currentValue() -> Self {
        do {
            guard let data = UserDefaults.shared.data(forKey: self.storeKey) else {
                return self.defaultValue
            }
            return try JSONDecoder().decode(Self.self, from: data)
        } catch {
            return self.defaultValue
        }
    }
}
