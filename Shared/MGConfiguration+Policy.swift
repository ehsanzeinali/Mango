import Foundation

extension MGConfiguration {
    public struct Policy: Codable {
        private struct Level: Codable {
            private var handshake = 4
            private var connIdle = 300
            private var uplinkOnly = 2
            private var downlinkOnly = 5
            private var statsUserUplink = false
            private var statsUserDownlink = false
            private var bufferSize = 4
        }
        private struct System: Codable {
            private var statsInboundUplink = false
            private var statsInboundDownlink = false
            private var statsOutboundUplink = true
            private var statsOutboundDownlink = true
        }
        private var levels = ["0": Level()]
        private var system = System()
        public static let defaultValue = MGConfiguration.Policy()
    }
}
