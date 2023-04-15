import Foundation

final class MGConfigurationEditViewModel: ObservableObject {
    
    let id: UUID
    @Published var name: String
    @Published var model: MGConfiguration.Outbound
    
    init(id: UUID, name: String, model: MGConfiguration.Outbound) {
        self.id = id
        self.name = name
        self.model = model
    }
    
    init(id: UUID, protocolType: MGConfiguration.Outbound.ProtocolType) {
        self.id = id
        self.name = ""
        self.model = MGConfiguration.Outbound(protocolType: protocolType)
    }
    
    func save() throws {
        let folderURL = MGConstant.configDirectory.appending(component: "\(self.id.uuidString)")
        let attributes = MGConfiguration.Attributes(
            alias: self.name.trimmingCharacters(in: .whitespacesAndNewlines),
            source: URL(string: "\(self.model.protocolType.rawValue)://")!,
            leastUpdated: Date()
        )
        if FileManager.default.fileExists(atPath: folderURL.path(percentEncoded: false)) {
            try FileManager.default.setAttributes([
                MGConfiguration.key: [MGConfiguration.Attributes.key: try JSONEncoder().encode(attributes)]
            ], ofItemAtPath: folderURL.path(percentEncoded: false))
        } else {
            try FileManager.default.createDirectory(
                at: folderURL,
                withIntermediateDirectories: true,
                attributes: [
                    MGConfiguration.key: [MGConfiguration.Attributes.key: try JSONEncoder().encode(attributes)]
                ]
            )
        }
        let destinationURL = folderURL.appending(component: "config.json")
        let data = try JSONEncoder().encode(self.model)
        FileManager.default.createFile(atPath: destinationURL.path(percentEncoded: false), contents: data)
    }
}
