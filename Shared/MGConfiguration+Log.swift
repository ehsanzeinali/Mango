import Foundation

extension MGConfiguration {
    
    public struct Log: Codable, Equatable, MGConfigurationPersistentModel {
        
        public enum Severity: String, Codable, Equatable, CaseIterable, Identifiable, CustomStringConvertible {
            
            public var id: Self { self }
            
            case unknown    = "Unknown"
            case error      = "Error"
            case warning    = "Warning"
            case info       = "Info"
            case debug      = "Debug"
            
            public var description: String { self.rawValue }
        }
        
        public var accessLogEnabled = false
        public var dnsLogEnabled = false
        public var errorLogSeverity = Severity.unknown
        
        public static let storeKey = "XRAY_LOG_DATA"
        public static let defaultValue = Log()
        
        private init() {}
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.accessLogEnabled = try container.decode(String.self, forKey: .access) != "none"
            self.dnsLogEnabled = try container.decode(Bool.self, forKey: .dnsLog)
            self.errorLogSeverity = try container.decode(Severity.self, forKey: .loglevel)
        }
        
        private enum CodingKeys: String, CodingKey {
            case access
            case error
            case loglevel
            case dnsLog
        }
        
        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(self.accessLogEnabled ? "" : "none", forKey: .access)
            try container.encode(self.errorLogSeverity != .unknown ? "" : "none", forKey: .error)
            try container.encode(self.errorLogSeverity, forKey: .loglevel)
            try container.encode(self.dnsLogEnabled, forKey: .dnsLog)
        }
    }
}
