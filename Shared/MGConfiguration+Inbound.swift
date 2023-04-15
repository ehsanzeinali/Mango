import Foundation

extension MGConfiguration {
    
    public struct Inbound: Codable, Equatable, MGConfigurationPersistentModel {
        
        public struct DestinationOverride: RawRepresentable, Codable, Hashable, CustomStringConvertible, CaseIterable {
            
            public let rawValue: String
            
            public init(rawValue: String) {
                self.rawValue = rawValue
            }
            
            public static let http      = DestinationOverride(rawValue: "http")
            public static let tls       = DestinationOverride(rawValue: "tls")
            public static let quic      = DestinationOverride(rawValue: "quic")
            public static let fakedns   = DestinationOverride(rawValue: "fakedns")
            
            public var description: String {
                switch self {
                case .http:
                    return "HTTP"
                case .tls:
                    return "TLS"
                case .quic:
                    return "QUIC"
                case .fakedns:
                    return "FakeDNS"
                default:
                    return self.rawValue
                }
            }
            
            public static let allCases: [DestinationOverride] = [.http, .tls, .quic, .fakedns]
        }
        
        public struct Sniffing: Codable, Equatable {
            public var enabled: Bool
            public var destOverride: Set<DestinationOverride>
            public var metadataOnly: Bool
            public var routeOnly: Bool
            public var excludedDomains: [String]
        }
        
        private struct Settings: Codable, Equatable {
            private var udp = true
            private var auth = "noauth"
        }
        
        private var listen = "[::1]"
        private var `protocol` = "socks"
        private var settings = Settings()
        private var tag = "socks-in"
        
        public var port: Int = 8080
        public var sniffing: Sniffing = Sniffing(
            enabled: true,
            destOverride: [.http, .tls],
            metadataOnly: false,
            routeOnly: false,
            excludedDomains: []
        )
        
        public static let storeKey = "XRAY_INBOUND_DATA"
        
        public static let defaultValue = MGConfiguration.Inbound()
    }
}
