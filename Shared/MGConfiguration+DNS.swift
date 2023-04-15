import Foundation

extension MGConfiguration {
    
    public struct DNS: Codable, Equatable, MGConfigurationPersistentModel {
        
        public enum QueryStrategy: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
            public var id: Self { self }
            case useIP      = "UseIP"
            case useIPv4    = "UseIPv4"
            case useIPv6    = "UseIPv6"
            public var description: String {
                return self.rawValue
            }
        }
        
        public struct Server: Codable, Equatable, Identifiable {
            public var __object__ = false
            private var __uuid__ = UUID()
            public var id: UUID { self.__uuid__ }
            public var address: String = ""
            public var port: Int = 0
            public var domains: [String] = []
            public var expectIPs: [String] = []
            public var skipFallback: Bool = false
            public var clientIP: String?
            private enum CodingKeys: CodingKey {
                case address
                case port
                case domains
                case expectIPs
                case skipFallback
                case clientIP
            }
            init() {}
            public init(from decoder: Decoder) throws {
                do {
                    let container = try decoder.singleValueContainer()
                    self.address = try container.decode(String.self)
                    self.__object__ = false
                    self.__uuid__ = UUID()
                } catch {
                    let container = try decoder.container(keyedBy: CodingKeys.self)
                    self.address = try container.decode(String.self, forKey: .address)
                    self.port = try container.decode(Int.self, forKey: .port)
                    self.domains = try container.decode([String].self, forKey: .domains)
                    self.expectIPs = try container.decode([String].self, forKey: .expectIPs)
                    self.skipFallback = try container.decode(Bool.self, forKey: .skipFallback)
                    self.clientIP = try container.decodeIfPresent(String.self, forKey: .clientIP)
                    self.__object__ = true
                    self.__uuid__ = UUID()
                }
            }
            public func encode(to encoder: Encoder) throws {
                if self.__object__ {
                    var container = encoder.container(keyedBy: CodingKeys.self)
                    try container.encode(self.address, forKey: .address)
                    try container.encode(self.port, forKey: .port)
                    try container.encode(self.domains, forKey: .domains)
                    try container.encode(self.expectIPs, forKey: .expectIPs)
                    try container.encode(self.skipFallback, forKey: .skipFallback)
                    try container.encodeIfPresent(self.clientIP, forKey: .clientIP)
                } else {
                    var container = encoder.singleValueContainer()
                    try container.encode(self.address)
                }
            }
        }
        
        public struct Host: Codable, Equatable, Identifiable {
            public var id: UUID = UUID()
            public var key: String = ""
            public var values: [String] = []
        }
                
        public var hosts: [Host]? = nil
        public var servers: [Server]? = nil
        public var clientIp: String? = nil
        public var queryStrategy: QueryStrategy = .useIP
        public var disableCache: Bool = false
        public var disableFallback: Bool = false
        public var disableFallbackIfMatch: Bool = false
        
        private enum CodingKeys: String, CodingKey {
            case hosts
            case servers
            case clientIp
            case queryStrategy
            case disableCache
            case disableFallback
            case disableFallbackIfMatch
            case tag
        }
        
        public init() {}
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let mapping = try container.decode(Optional<[String: [String]]>.self, forKey: .hosts)
            self.hosts = mapping.flatMap({ mapping in
                mapping.reduce(into: [Host]()) { result, pair in
                    result.append(Host(id: UUID(), key: pair.key, values: pair.value))
                }
            })
            self.servers = try container.decode(Optional<[Server]>.self, forKey: .servers)
            self.clientIp = try container.decode(Optional<String>.self, forKey: .clientIp)
            self.queryStrategy = try container.decode(QueryStrategy.self, forKey: .queryStrategy)
            self.disableCache = try container.decode(Bool.self, forKey: .disableCache)
            self.disableFallback = try container.decode(Bool.self, forKey: .disableFallback)
            self.disableFallbackIfMatch = try container.decode(Bool.self, forKey: .disableFallbackIfMatch)
        }
        
        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            let mapping = self.hosts.flatMap { hosts in
                hosts.reduce(into: [String: [String]]()) { result, host in
                    result[host.key] = host.values
                }
            }
            try container.encode(mapping, forKey: .hosts)
            try container.encode(self.servers, forKey: .servers)
            try container.encode(self.clientIp, forKey: .clientIp)
            try container.encode(self.queryStrategy, forKey: .queryStrategy)
            try container.encode(self.disableCache, forKey: .disableCache)
            try container.encode(self.disableFallback, forKey: .disableFallback)
            try container.encode(self.disableFallbackIfMatch, forKey: .disableFallbackIfMatch)
            try container.encode("dns-in", forKey: .tag)
        }
        
        public static var storeKey = "XRAY_DNS_DATA"
        
        public static var defaultValue = DNS()
    }
}

