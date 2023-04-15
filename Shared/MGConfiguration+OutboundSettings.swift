import Foundation

extension MGConfiguration {
    
    public struct OutboundSettings: Codable, Equatable, MGConfigurationPersistentModel {
        
        public var dns          = Outbound(protocolType: .dns)
        public var freedom      = Outbound(protocolType: .freedom)
        public var blackhole    = Outbound(protocolType: .blackhole)
        public var order        = Outbound.Tag.allCases

        public static let storeKey = "XRAY_OUTBOUND_DATA"
        
        public static let defaultValue = OutboundSettings()
    }
}
