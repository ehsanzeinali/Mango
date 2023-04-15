import Foundation

extension MGConfiguration {    
    public struct Outbound: Codable, Equatable {
        public enum Tag: String, Identifiable, CaseIterable, CustomStringConvertible, Codable, Equatable {
            public var id: Self { self }
            case proxy, freedom, blackhole, dns
            public var description: String {
                switch self {
                case .proxy:
                    return "Proxy"
                case .freedom:
                    return "Freedom"
                case .blackhole:
                    return "Blackhole"
                case .dns:
                    return "DNS"
                }
            }
        }
        public struct DNSSettings: Codable, Equatable {
            public enum Network: String, Codable, Identifiable, CustomStringConvertible, CaseIterable, Equatable {
                public var id: Self { self }
                case tcp, udp, inherit
                public var description: String {
                    switch self {
                    case .tcp:
                        return "TCP"
                    case .udp:
                        return "UDP"
                    case .inherit:
                        return "Inherit"
                    }
                }
                public init(from decoder: Decoder) throws {
                    let coantiner = try decoder.singleValueContainer()
                    self = Network(rawValue: try coantiner.decode(String.self)) ?? .inherit
                }
                public func encode(to encoder: Encoder) throws {
                    var container = encoder.singleValueContainer()
                    if self == .inherit {
                        try container.encodeNil()
                    } else {
                        try container.encode(self.rawValue)
                    }
                }
            }
            public var network: Network = .inherit
            public var address: String?
            public var port: Int?
        }
        
        public struct FreedomSettings: Codable, Equatable {
            public enum DomainStrategy: String, Codable, Identifiable, CaseIterable, CustomStringConvertible {
                public var id: Self { self }
                case asIs       = "AsIs"
                case useIP      = "UseIP"
                case useIPv4    = "UseIPv4"
                case useIPv6    = "UseIPv6"
                public var description: String {
                    self.rawValue
                }
            }
            public var domainStrategy: DomainStrategy = .asIs
            public var redirect: String?
            public var userLevel: Int = 0
        }
        
        public struct BlackholeSettings: Codable, Equatable {
            public enum ResponseType: String, Codable, Identifiable, CaseIterable, CustomStringConvertible {
                public var id: Self { self }
                case none, http
                public var description: String {
                    switch self {
                    case .none:
                        return "None"
                    case .http:
                        return "HTTP"
                    }
                }
            }
            public struct Response: Codable, Equatable {
                public var type: ResponseType = .none
            }
            public var response = Response()
        }
        public enum ProtocolType: String, Identifiable, CaseIterable, CustomStringConvertible, Codable, Equatable {
            public var id: Self { self }
            case vless, vmess, trojan, shadowsocks, dns, freedom, blackhole
            public var description: String {
                switch self {
                case .vless:
                    return "VLESS"
                case .vmess:
                    return "VMess"
                case .trojan:
                    return "Trojan"
                case .shadowsocks:
                    return "Shadowsocks"
                case .dns:
                    return "DNS"
                case .freedom:
                    return "Freedom"
                case .blackhole:
                    return "Blackhole"
                }
            }
            public static let allCases: [MGConfiguration.Outbound.ProtocolType] = [.vless, .vmess, .trojan, .shadowsocks]
        }
        public enum Encryption: String, Identifiable, CustomStringConvertible, Codable, Equatable {
            public var id: Self { self }
            case aes_128_gcm        = "aes-128-gcm"
            case chacha20_poly1305  = "chacha20-poly1305"
            case auto               = "auto"
            case none               = "none"
            case zero               = "zero"
            public var description: String {
                switch self {
                case .aes_128_gcm:
                    return "AES-128-GCM"
                case .chacha20_poly1305:
                    return "Chacha20-Poly1305"
                case .auto:
                    return "Auto"
                case .none:
                    return "None"
                case .zero:
                    return "Zero"
                }
            }
            public static let vmess: [Encryption] = [.chacha20_poly1305, .aes_128_gcm, .auto, .none, .zero]
            public static let quic:  [Encryption] = [.chacha20_poly1305, .aes_128_gcm, .none]
        }
        public struct StreamSettings: Codable, Equatable {
            public enum Transport: String, Identifiable, CaseIterable, CustomStringConvertible, Codable, Equatable {
                public var id: Self { self }
                case tcp, kcp, ws, http, quic, grpc
                public var description: String {
                    switch self {
                    case .tcp:
                        return "TCP"
                    case .kcp:
                        return "mKCP"
                    case .ws:
                        return "WebSocket"
                    case .http:
                        return "HTTP/2"
                    case .quic:
                        return "QUIC"
                    case .grpc:
                        return "gRPC"
                    }
                }
            }
            public enum Security: String, Identifiable, CaseIterable, CustomStringConvertible, Codable, Equatable {
                public var id: Self { self }
                case none, tls, reality
                public var description: String {
                    switch self {
                    case .none:
                        return "None"
                    case .tls:
                        return "TLS"
                    case .reality:
                        return "Reality"
                    }
                }
            }
            public enum HeaderType: String, Identifiable, CaseIterable, CustomStringConvertible, Codable, Equatable {
                public var id: Self { self }
                case none           = "none"
                case srtp           = "srtp"
                case utp            = "utp"
                case wechat_video   = "wechat-video"
                case dtls           = "dtls"
                case wireguard      = "wireguard"
                public var description: String {
                    switch self {
                    case .none:
                        return "None"
                    case .srtp:
                        return "SRTP"
                    case .utp:
                        return "UTP"
                    case .wechat_video:
                        return "Wecaht Video"
                    case .dtls:
                        return "DTLS"
                    case .wireguard:
                        return "Wireguard"
                    }
                }
            }
            public enum Fingerprint: String, Identifiable, CaseIterable, CustomStringConvertible, Codable, Equatable {
                public var id: Self { self }
                case chrome     = "chrome"
                case firefox    = "firefox"
                case safari     = "safari"
                case ios        = "ios"
                case android    = "android"
                case edge       = "edge"
                case _360       = "360"
                case qq         = "qq"
                case random     = "random"
                case randomized = "randomized"
                public var description: String {
                    switch self {
                    case .chrome:
                        return "Chrome"
                    case .firefox:
                        return "Firefox"
                    case .safari:
                        return "Safari"
                    case .ios:
                        return "iOS"
                    case .android:
                        return "Android"
                    case .edge:
                        return "Edge"
                    case ._360:
                        return "360"
                    case .qq:
                        return "QQ"
                    case .random:
                        return "Random"
                    case .randomized:
                        return "Randomized"
                    }
                }
            }
            public enum ALPN: String, Identifiable, CaseIterable, CustomStringConvertible, Codable, Equatable {
                public var id: Self { self }
                case h2         = "h2"
                case http1_1    = "http/1.1"
                public var description: String {
                    switch self {
                    case .h2:
                        return "H2"
                    case .http1_1:
                        return "HTTP/1.1"
                    }
                }
            }
            public struct TLSSettings: Codable, Equatable {
                public var serverName: String = ""
                public var allowInsecure: Bool = false
                public var alpn: Set<ALPN> = Set(ALPN.allCases)
                public var fingerprint: Fingerprint = .chrome
            }
            public struct RealitySettings: Codable, Equatable {
                public var show: Bool = false
                public var fingerprint: Fingerprint = .chrome
                public var serverName: String = ""
                public var publicKey: String = ""
                public var shortId: String = ""
                public var spiderX: String = ""
            }
            public struct TCPSettings: Codable, Equatable {
                public struct Header: Codable, Equatable {
                    public var type: HeaderType = .none
                }
                public var header = Header()
            }
            public struct KCPSettings: Codable, Equatable {
                public struct Header: Codable, Equatable {
                    public var type: HeaderType = .none
                }
                public var mtu: Int = 1350
                public var tti: Int = 20
                public var uplinkCapacity: Int = 5
                public var downlinkCapacity: Int = 20
                public var congestion: Bool = false
                public var readBufferSize: Int = 1
                public var writeBufferSize: Int = 1
                public var header = Header()
                public var seed: String = ""
            }
            public struct WSSettings: Codable, Equatable {
                public var path: String = "/"
                public var headers: [String: String] = [:]
            }
            public struct HTTPSettings: Codable, Equatable {
                public var host: [String] = []
                public var path: String = "/"
            }
            public struct QUICSettings: Codable, Equatable {
                public struct Header: Codable, Equatable {
                    public var type: HeaderType = .none
                }
                public var security = Encryption.none
                public var key: String = ""
                public var header = Header()
            }
            public struct GRPCSettings: Codable, Equatable {
                public var serviceName: String = ""
                public var multiMode: Bool = false
            }
            public var security = Security.none
            public var tlsSettings = TLSSettings()
            public var realitySettings = RealitySettings()
            public var transport = Transport.tcp
            public var tcpSettings = TCPSettings()
            public var kcpSettings = KCPSettings()
            public var wsSettings = WSSettings()
            public var httpSettings = HTTPSettings()
            public var quicSettings = QUICSettings()
            public var grpcSettings = GRPCSettings()
            private enum CodingKeys: String, CodingKey {
                case security
                case tlsSettings
                case realitySettings
                case transport = "network"
                case tcpSettings
                case kcpSettings
                case wsSettings
                case httpSettings
                case quicSettings
                case grpcSettings
            }
            public init() {}
            public init(from decoder: Decoder) throws {
                let container: KeyedDecodingContainer = try decoder.container(keyedBy: CodingKeys.self)
                self.security = try container.decode(Security.self, forKey: .security)
                switch self.security {
                case .none:
                    break
                case .tls:
                    self.tlsSettings = try container.decode(TLSSettings.self, forKey: .tlsSettings)
                case .reality:
                    self.realitySettings = try container.decode(RealitySettings.self, forKey: .realitySettings)
                }
                self.transport = try container.decode(Transport.self, forKey: .transport)
                switch self.transport {
                case .tcp:
                    self.tcpSettings = try container.decode(TCPSettings.self, forKey: .tcpSettings)
                case .kcp:
                    self.kcpSettings = try container.decode(KCPSettings.self, forKey: .kcpSettings)
                case .ws:
                    self.wsSettings = try container.decode(WSSettings.self, forKey: .wsSettings)
                case .http:
                    self.httpSettings = try container.decode(HTTPSettings.self, forKey: .httpSettings)
                case .quic:
                    self.quicSettings = try container.decode(QUICSettings.self, forKey: .quicSettings)
                case .grpc:
                    self.grpcSettings = try container.decode(GRPCSettings.self, forKey: .grpcSettings)
                }
            }
            public func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: CodingKeys.self)
                try container.encode(self.security, forKey: .security)
                switch self.security {
                case .none:
                    break
                case .tls:
                    try container.encode(self.tlsSettings, forKey: .tlsSettings)
                case .reality:
                    try container.encode(self.realitySettings, forKey: .realitySettings)
                }
                try container.encode(self.transport, forKey: .transport)
                switch self.transport {
                case .tcp:
                    try container.encode(self.tcpSettings, forKey: .tcpSettings)
                case .kcp:
                    try container.encode(self.kcpSettings, forKey: .kcpSettings)
                case .ws:
                    try container.encode(self.wsSettings, forKey: .wsSettings)
                case .http:
                    try container.encode(self.httpSettings, forKey: .httpSettings)
                case .quic:
                    try container.encode(self.quicSettings, forKey: .quicSettings)
                case .grpc:
                    try container.encode(self.grpcSettings, forKey: .grpcSettings)
                }
            }
        }
        public struct VLESSSettings: Codable, Equatable {
            public enum Flow: String, Identifiable, CaseIterable, CustomStringConvertible, Codable {
                public var id: Self { self }
                case none                       = "none"
                case xtls_rprx_vision           = "xtls-rprx-vision"
                case xtls_rprx_vision_udp443    = "xtls-rprx-vision-udp443"
                public var description: String {
                    switch self {
                    case .none:
                        return "None"
                    case .xtls_rprx_vision:
                        return "XTLS-RPRX-Vision"
                    case .xtls_rprx_vision_udp443:
                        return "XTLS-RPRX-Vision-UDP443"
                    }
                }
            }
            public struct User: Codable, Equatable {
                public var id: String = ""
                public var encryption: String = "none"
                public var flow = Flow.none
            }
            public var address: String = ""
            public var port: Int = 443
            public var user: User = User()
            private enum CodingKeys: CodingKey {
                case address
                case port
                case users
            }
            public init() {}
            public init(from decoder: Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                self.address = try container.decode(String.self, forKey: .address)
                self.port = try container.decode(Int.self, forKey: .port)
                if let first = try container.decode([User].self, forKey: .users).first {
                    self.user = first
                } else {
                    throw NSError.newError("VLESS no user data")
                }
            }
            public func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: CodingKeys.self)
                try container.encode(self.address, forKey: .address)
                try container.encode(self.port, forKey: .port)
                try container.encode([self.user], forKey: .users)
            }
        }
        public struct VMessSettings: Codable, Equatable {
            public struct User: Codable, Equatable {
                public var id: String = ""
                public var alterId: Int = 0
                public var security = Encryption.auto
            }
            public var address: String = ""
            public var port: Int = 443
            public var user: User = User()
            private enum CodingKeys: CodingKey {
                case address
                case port
                case users
            }
            public init() {}
            public init(from decoder: Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                self.address = try container.decode(String.self, forKey: .address)
                self.port = try container.decode(Int.self, forKey: .port)
                if let first = try container.decode([User].self, forKey: .users).first {
                    self.user = first
                } else {
                    throw NSError.newError("VMess no user data")
                }
            }
            public func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: CodingKeys.self)
                try container.encode(self.address, forKey: .address)
                try container.encode(self.port, forKey: .port)
                try container.encode([self.user], forKey: .users)
            }
        }
        public struct TrojanSettings: Codable, Equatable {
            public var address: String = ""
            public var port: Int = 443
            public var password: String = ""
            public var email: String = ""
        }
        public struct ShadowsocksSettings: Codable, Equatable {
            public enum Method: String, Identifiable, CustomStringConvertible, Codable, CaseIterable, Equatable {
                public var id: Self { self }
                case _2022_blake3_aes_128_gcm       = "2022-blake3-aes-128-gcm"
                case _2022_blake3_aes_256_gcm       = "2022-blake3-aes-256-gcm"
                case _2022_blake3_chacha20_poly1305 = "2022-blake3-chacha20-poly1305"
                case aes_256_gcm                    = "aes-256-gcm"
                case aes_128_gcm                    = "aes-128-gcm"
                case chacha20_poly1305              = "chacha20-poly1305"
                case chacha20_ietf_poly1305         = "chacha20-ietf-poly1305"
                case plain                          = "plain"
                case none                           = "none"
                public var description: String {
                    switch self {
                    case ._2022_blake3_aes_128_gcm:
                        return "2022-Blake3-AES-128-GCM"
                    case ._2022_blake3_aes_256_gcm:
                        return "2022-Blake3-AES-256-GCM"
                    case ._2022_blake3_chacha20_poly1305:
                        return "2022-Blake3-Chacha20-Poly1305"
                    case .aes_256_gcm:
                        return "AES-256-GCM"
                    case .aes_128_gcm:
                        return "AES-128-GCM"
                    case .chacha20_poly1305:
                        return "Chacha20-Poly1305"
                    case .chacha20_ietf_poly1305:
                        return "Chacha20-ietf-Poly1305"
                    case .none:
                        return "None"
                    case .plain:
                        return "Plain"
                    }
                }
            }
            public var address: String = ""
            public var port: Int = 443
            public var password: String = ""
            public var email: String = ""
            public var method = Method.none
            public var uot: Bool = false
            public var level: Int = 0
        }
        public var protocolType: ProtocolType
        public var vlessSettings = VLESSSettings()
        public var vmessSettings = VMessSettings()
        public var trojanSettings = TrojanSettings()
        public var shadowsocksSettings = ShadowsocksSettings()
        public var dnsSettings = DNSSettings()
        public var freedomSettings = FreedomSettings()
        public var blackholeSettings = BlackholeSettings()
        public var streamSettings = StreamSettings()
        private enum CodingKeys: String, CodingKey {
            case protocolType = "protocol"
            case streamSettings
            case settings
            case vnext
            case servers
            case tag
        }
        init(protocolType: ProtocolType) {
            self.protocolType = protocolType
        }
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.protocolType = try container.decode(ProtocolType.self, forKey: .protocolType)
            switch self.protocolType {
            case .vless:
                let settings = try container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                self.vlessSettings = try settings.decode([VLESSSettings].self, forKey: .vnext)[0]
            case .vmess:
                let settings = try container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                self.vmessSettings = try settings.decode([VMessSettings].self, forKey: .vnext)[0]
            case .trojan:
                let settings = try container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                self.trojanSettings = try settings.decode([TrojanSettings].self, forKey: .servers)[0]
            case .shadowsocks:
                let settings = try container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                self.shadowsocksSettings = try settings.decode([ShadowsocksSettings].self, forKey: .servers)[0]
            case .dns:
                self.dnsSettings = try container.decode(DNSSettings.self, forKey: .settings)
            case .freedom:
                self.freedomSettings = try container.decode(FreedomSettings.self, forKey: .settings)
            case .blackhole:
                self.blackholeSettings = try container.decode(BlackholeSettings.self, forKey: .settings)
            }
            switch self.protocolType {
            case .vless, .vmess, .trojan, .shadowsocks:
                self.streamSettings = try container.decode(StreamSettings.self, forKey: .streamSettings)
            case .dns, .freedom, .blackhole:
                break
            }
        }
        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(self.protocolType, forKey: .protocolType)
            switch self.protocolType {
            case .vless:
                var settings = container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                try settings.encode([self.vlessSettings], forKey: .vnext)
            case .vmess:
                var settings = container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                try settings.encode([self.vmessSettings], forKey: .vnext)
            case .trojan:
                var settings = container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                try settings.encode([self.trojanSettings], forKey: .servers)
            case .shadowsocks:
                var settings = container.nestedContainer(keyedBy: CodingKeys.self, forKey: .settings)
                try settings.encode([self.shadowsocksSettings], forKey: .servers)
            case .dns:
                try container.encode(self.dnsSettings, forKey: .settings)
            case .freedom:
                try container.encode(self.freedomSettings, forKey: .settings)
            case .blackhole:
                try container.encode(self.blackholeSettings, forKey: .settings)
            }
            switch self.protocolType {
            case .vless, .vmess, .trojan, .shadowsocks:
                try container.encode(self.streamSettings, forKey: .streamSettings)
                try container.encode(Tag.proxy.rawValue, forKey: .tag)
            case .dns:
                try container.encode(Tag.dns.rawValue, forKey: .tag)
            case .freedom:
                try container.encode(Tag.freedom.rawValue, forKey: .tag)
            case .blackhole:
                try container.encode(Tag.blackhole.rawValue, forKey: .tag)
            }
        }
    }
}
