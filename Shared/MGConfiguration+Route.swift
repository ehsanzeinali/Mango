import Foundation

extension MGConfiguration {
    
    public struct Route: Codable, Equatable, MGConfigurationPersistentModel {
        
        public enum DomainStrategy: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
            public var id: Self { self }
            case asIs           = "AsIs"
            case ipIfNonMatch   = "IPIfNonMatch"
            case ipOnDemand     = "IPOnDemand"
            public var description: String {
                return self.rawValue
            }
        }
        
        public enum DomainMatcher: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
            public var id: Self { self }
            case hybrid, linear
            public var description: String {
                switch self {
                case .hybrid:
                    return "Hybrid"
                case .linear:
                    return "Linear"
                }
            }
        }
        
        public enum Inbound: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
            public var id: Self { self }
            case socks  = "socks-in"
            case dns    = "dns-in"
            public var description: String {
                switch self {
                case .socks:
                    return "Socks"
                case .dns:
                    return "DNS"
                }
            }
        }
        
        public enum Protocol_: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
            public var id: Self { self }
            case http, tls, bittorrent
            public var description: String {
                switch self {
                case .http:
                    return "HTTP"
                case .tls:
                    return "TLS"
                case .bittorrent:
                    return "Bittorrent"
                }
            }
        }
        
        public enum Network: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
            public var id: Self { self }
            case tcp, udp
            public var description: String {
                switch self {
                case .tcp:
                    return "TCP"
                case .udp:
                    return "UDP"
                }
            }
        }
        
        public struct Rule: Codable, Equatable, Identifiable {
            
            public var id: UUID { self.__id__ }
            
            public var domainMatcher: DomainMatcher = .hybrid
            public var type: String = "field"
            public var domain: [String]?
            public var ip: [String]?
            public var port: String?
            public var sourcePort: String?
            public var network: Set<Network>?
            public var source: [String]?
            public var user: [String]?
            public var inboundTag: Set<Inbound>?
            public var `protocol`: Set<Protocol_>?
            public var attrs: String?
            public var outboundTag: Outbound.Tag = .freedom
            public var balancerTag: String?
            
            public var __id__: UUID = UUID()
            public var __name__: String = ""
            public var __enabled__: Bool = false
            
            public var __defaultName__: String {
                "Rule_\(self.__id__.uuidString)"
            }
            
            public init() {}
            
            public init(from decoder: Decoder) throws {
                let container: KeyedDecodingContainer<MGConfiguration.Route.Rule.CodingKeys> = try decoder.container(keyedBy: MGConfiguration.Route.Rule.CodingKeys.self)
                self.domainMatcher = try container.decode(MGConfiguration.Route.DomainMatcher.self, forKey: MGConfiguration.Route.Rule.CodingKeys.domainMatcher)
                self.type = try container.decode(String.self, forKey: MGConfiguration.Route.Rule.CodingKeys.type)
                self.domain = try container.decodeIfPresent([String].self, forKey: MGConfiguration.Route.Rule.CodingKeys.domain)
                self.ip = try container.decodeIfPresent([String].self, forKey: MGConfiguration.Route.Rule.CodingKeys.ip)
                self.port = try container.decodeIfPresent(String.self, forKey: MGConfiguration.Route.Rule.CodingKeys.port)
                self.sourcePort = try container.decodeIfPresent(String.self, forKey: MGConfiguration.Route.Rule.CodingKeys.sourcePort)
                if let networkString = try container.decodeIfPresent(String.self, forKey: .network) {
                    self.network = Set(networkString.components(separatedBy: ",").compactMap(Network.init(rawValue:)))
                } else {
                    self.network = nil
                }
                self.network = try container.decodeIfPresent(Set<MGConfiguration.Route.Network>.self, forKey: MGConfiguration.Route.Rule.CodingKeys.network)
                self.source = try container.decodeIfPresent([String].self, forKey: MGConfiguration.Route.Rule.CodingKeys.source)
                self.user = try container.decodeIfPresent([String].self, forKey: MGConfiguration.Route.Rule.CodingKeys.user)
                self.inboundTag = try container.decodeIfPresent(Set<MGConfiguration.Route.Inbound>.self, forKey: MGConfiguration.Route.Rule.CodingKeys.inboundTag)
                self.protocol = try container.decodeIfPresent(Set<MGConfiguration.Route.Protocol_>.self, forKey: MGConfiguration.Route.Rule.CodingKeys.protocol)
                self.attrs = try container.decodeIfPresent(String.self, forKey: MGConfiguration.Route.Rule.CodingKeys.attrs)
                self.outboundTag = try container.decode(MGConfiguration.Outbound.Tag.self, forKey: MGConfiguration.Route.Rule.CodingKeys.outboundTag)
                self.balancerTag = try container.decodeIfPresent(String.self, forKey: MGConfiguration.Route.Rule.CodingKeys.balancerTag)
                self.__id__ = try container.decode(UUID.self, forKey: MGConfiguration.Route.Rule.CodingKeys.__id__)
                self.__name__ = try container.decode(String.self, forKey: MGConfiguration.Route.Rule.CodingKeys.__name__)
                self.__enabled__ = try container.decode(Bool.self, forKey: MGConfiguration.Route.Rule.CodingKeys.__enabled__)
            }
            
            private enum CodingKeys: CodingKey {
                case domainMatcher
                case type
                case domain
                case ip
                case port
                case sourcePort
                case network
                case source
                case user
                case inboundTag
                case `protocol`
                case attrs
                case outboundTag
                case balancerTag
                case __id__
                case __name__
                case __enabled__
            }
            
            public func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: MGConfiguration.Route.Rule.CodingKeys.self)
                try container.encode(self.domainMatcher, forKey: MGConfiguration.Route.Rule.CodingKeys.domainMatcher)
                try container.encode(self.type, forKey: MGConfiguration.Route.Rule.CodingKeys.type)
                try container.encodeIfPresent(self.domain, forKey: MGConfiguration.Route.Rule.CodingKeys.domain)
                try container.encodeIfPresent(self.ip, forKey: MGConfiguration.Route.Rule.CodingKeys.ip)
                try container.encodeIfPresent(self.port, forKey: MGConfiguration.Route.Rule.CodingKeys.port)
                try container.encodeIfPresent(self.sourcePort, forKey: MGConfiguration.Route.Rule.CodingKeys.sourcePort)
                let networkString: String? = {
                    guard let network = network, !network.isEmpty else {
                        return nil
                    }
                    var reval: [Network] = []
                    if network.contains(.tcp) {
                        reval.append(.tcp)
                    }
                    if network.contains(.udp) {
                        reval.append(.udp)
                    }
                    return reval.map(\.rawValue).joined(separator: ",")
                }()
                try container.encodeIfPresent(networkString, forKey: MGConfiguration.Route.Rule.CodingKeys.network)
                try container.encodeIfPresent(self.source, forKey: MGConfiguration.Route.Rule.CodingKeys.source)
                try container.encodeIfPresent(self.user, forKey: MGConfiguration.Route.Rule.CodingKeys.user)
                try container.encodeIfPresent(self.inboundTag, forKey: MGConfiguration.Route.Rule.CodingKeys.inboundTag)
                try container.encodeIfPresent(self.protocol, forKey: MGConfiguration.Route.Rule.CodingKeys.protocol)
                try container.encodeIfPresent(self.attrs, forKey: MGConfiguration.Route.Rule.CodingKeys.attrs)
                try container.encode(self.outboundTag, forKey: MGConfiguration.Route.Rule.CodingKeys.outboundTag)
                try container.encodeIfPresent(self.balancerTag, forKey: MGConfiguration.Route.Rule.CodingKeys.balancerTag)
                try container.encode(self.__id__, forKey: MGConfiguration.Route.Rule.CodingKeys.__id__)
                try container.encode(self.__name__, forKey: MGConfiguration.Route.Rule.CodingKeys.__name__)
                try container.encode(self.__enabled__, forKey: MGConfiguration.Route.Rule.CodingKeys.__enabled__)
            }
        }
        
        public struct Balancer: Codable, Equatable {
            var tag: String
            var selector: [String] = []
        }
        
        public var domainStrategy: DomainStrategy = .asIs
        public var domainMatcher: DomainMatcher = .hybrid
        public var rules: [Rule] = []
        public var balancers: [Balancer] = []
                
        public static let storeKey = "XRAY_ROUTE_DATA"
        
        public static let defaultValue = MGConfiguration.Route()
    }
    
}
