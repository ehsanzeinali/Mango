import NetworkExtension
import XrayKit
import Tun2SocksKit
import os

extension MGConstant {
    static let cachesDirectory = URL(filePath: NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true)[0])
}

class PacketTunnelProvider: NEPacketTunnelProvider, XrayClientProtocol, XrayOSLoggerProtocol {
    
    private let instance = XrayInstance()
    
    private let logger = Logger(subsystem: "com.ehsan.Mango.XrayTunnel", category: "Core")
    
    override init() {
        super.init()
        XrayRegisterOSLogger(self)
    }
    
    override func startTunnel(options: [String : NSObject]? = nil) async throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        settings.mtu = 9000
        let netowrk = MGNetworkModel.current
        settings.ipv4Settings = {
            let settings = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
            settings.includedRoutes = [NEIPv4Route.default()]
            if netowrk.hideVPNIcon {
                settings.excludedRoutes = [NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "255.0.0.0")]
            }
            return settings
        }()
        settings.ipv6Settings = {
            guard netowrk.ipv6Enabled else {
                return nil
            }
            let settings = NEIPv6Settings(addresses: ["fd6e:a81b:704f:1211::1"], networkPrefixLengths: [64])
            settings.includedRoutes = [NEIPv6Route.default()]
            if netowrk.hideVPNIcon {
                settings.excludedRoutes = [NEIPv6Route(destinationAddress: "::", networkPrefixLength: 128)]
            }
            return settings
        }()
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"])
        try await self.setTunnelNetworkSettings(settings)
        do {
            try self.run()
        } catch {
            MGNotification.send(title: "", subtitle: "", body: error.localizedDescription)
            throw error
        }
    }
    
    private func run() throws {
        guard let id = UserDefaults.shared.string(forKey: MGConfiguration.currentStoreKey), !id.isEmpty else {
            throw NSError.newError("当前无有效配置")
        }
        var port: Int = 0
        let data = try MGConfiguration(uuidString: id).loadData(inboundPort: &port)
        let path = MGConstant.cachesDirectory.appending(component: "config.json").path(percentEncoded: false)
        guard FileManager.default.createFile(atPath: path, contents: data) else {
            throw NSError.newError("Xray 配置文件写入失败")
        }
        try self.instance.run(self)
        let config = """
        tunnel:
          mtu: 9000
        socks5:
          port: \(port)
          address: ::1
          udp: 'udp'
        misc:
          task-stack-size: 20480
          connect-timeout: 5000
          read-write-timeout: 60000
          log-file: stderr
          log-level: error
          limit-nofile: 65535
        """
        let configurationFilePath = MGConstant.cachesDirectory.appending(component: "config.yml").path(percentEncoded: false)
        guard FileManager.default.createFile(atPath: configurationFilePath, contents: config.data(using: .utf8)!) else {
            throw NSError.newError("Tunnel 配置文件写入失败")
        }
        DispatchQueue.global(qos: .userInitiated).async {
            NSLog("HEV_SOCKS5_TUNNEL_MAIN: \(Socks5Tunnel.run(withConfig: configurationFilePath))")
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason) async {
        let message: String
        switch reason {
        case .none:
            message = "No specific reason."
        case .userInitiated:
            message = "The user stopped the provider."
        case .providerFailed:
            message = "The provider failed."
        case .noNetworkAvailable:
            message = "There is no network connectivity."
        case .unrecoverableNetworkChange:
            message = "The device attached to a new network."
        case .providerDisabled:
            message = "The provider was disabled."
        case .authenticationCanceled:
            message = "The authentication process was cancelled."
        case .configurationFailed:
            message = "The provider could not be configured."
        case .idleTimeout:
            message = "The provider was idle for too long."
        case .configurationDisabled:
            message = "The associated configuration was disabled."
        case .configurationRemoved:
            message = "The associated configuration was deleted."
        case .superceded:
            message = "A high-priority configuration was started."
        case .userLogout:
            message = "The user logged out."
        case .userSwitch:
            message = "The active user changed."
        case .connectionFailed:
            message = "Failed to establish connection."
        case .sleep:
            message = "The device went to sleep and disconnectOnSleep is enabled in the configuration."
        case .appUpdate:
            message = "The NEProvider is being updated."
        @unknown default:
            return
        }
        MGNotification.send(title: "", subtitle: "", body: message)
    }
    
    func onAccessLog(_ message: String?) {
        message.flatMap { logger.log("\($0, privacy: .public)") }
    }
    
    func onDNSLog(_ message: String?) {
        message.flatMap { logger.log("\($0, privacy: .public)") }
    }
    
    func onGeneralMessage(_ severity: String?, message: String?) {
        guard let level = severity.flatMap(MGConfiguration.Log.Severity.init(rawValue:)),
              let message = message, !message.isEmpty else {
            return
        }
        switch level {
        case .debug:
            logger.debug("\(message, privacy: .public)")
        case .info:
            logger.info("\(message, privacy: .public)")
        case .warning:
            logger.warning("\(message, privacy: .public)")
        case .error:
            logger.error("\(message, privacy: .public)")
        case .unknown:
            break
        }
    }
    
    func onPrepare(_ env: XrayEnvironmentProtocol?) throws {
        try env.flatMap {
            try $0.set("XRAY_LOCATION_CONFIG", value: MGConstant.cachesDirectory.path(percentEncoded: false))
            try $0.set("XRAY_LOCATION_ASSET", value: MGConstant.assetDirectory.path(percentEncoded: false))
        }
    }
    
    func onServerRunning() {}
    
    func onTrafficUpdate(_ up: Int64, down: Int64) {
        UserDefaults.shared.set(up, forKey: "XRAY_PROXY_TRAFFIC_UP")
        UserDefaults.shared.set(down, forKey: "XRAY_PROXY_TRAFFIC_DOWN")
    }
}

extension MGConfiguration {
    
    private struct Model: Encodable {
        let log: Log
        let dns: DNS
        let routing: Route
        let inbounds: [Inbound]
        let outbounds: [Outbound]
        let stats = Statistics.defaultValue
        let policy = Policy.defaultValue
    }
    
    func loadData(inboundPort: inout Int) throws -> Data {
        let inbound: Inbound = {
            var reval = Inbound.currentValue()
            if reval.sniffing.destOverride.count == 4 {
                reval.sniffing.destOverride = [Inbound.DestinationOverride(rawValue: "fakedns+others")]
            }
            inboundPort = reval.port
            return reval
        }()
        let data = try Data(contentsOf: MGConstant.configDirectory.appending(component: "\(self.id)/config.json"))
        if self.attributes.source.scheme.flatMap(MGConfiguration.Outbound.ProtocolType.init(rawValue:)) == nil {
            return data
        } else {
            let routing: Route = {
                var reval = Route.currentValue()
                reval.rules = reval.rules.filter(\.__enabled__)
                return reval
            }()
            let outboundSettings = OutboundSettings.currentValue()
            let outbounds = try outboundSettings.order.map { tag in
                switch tag {
                case .proxy:
                    return try JSONDecoder().decode(MGConfiguration.Outbound.self, from: data)
                case .dns:
                    return outboundSettings.dns
                case .freedom:
                    return outboundSettings.freedom
                case .blackhole:
                    return outboundSettings.blackhole
                }
            }
            return try JSONEncoder().encode(
                Model(
                    log: Log.currentValue(),
                    dns: DNS.currentValue(),
                    routing: routing,
                    inbounds: [inbound],
                    outbounds: outbounds
                )
            )
        }
    }
}
