import SwiftUI

struct MGAssetView: View {
    
    @Environment(\.dataSizeFormatter) private var dataSizeFormatter

    @ObservedObject private var assetViewModel: MGAssetViewModel

    init(assetViewModel: MGAssetViewModel) {
        self._assetViewModel = ObservedObject(initialValue: assetViewModel)
    }
    
    var body: some View {
        Form {
            Section {
                ForEach(assetViewModel.items) { item in
                    HStack {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(item.url.lastPathComponent)
                            TimelineView(.periodic(from: Date(), by: 1)) { _ in
                                Text(item.date.formatted(.relative(presentation: .numeric)))
                                    .lineLimit(1)
                                    .foregroundColor(.secondary)
                                    .font(.callout)
                            }
                        }
                        Spacer()
                        Text(dataSizeFormatter.string(from: item.size) ?? "-")
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button("Delete", role: .destructive) {
                            do {
                                try assetViewModel.delete(item: item)
                            } catch {
                                debugPrint(error.localizedDescription)
                            }
                        }
                    }
                }
            } header: {
                Text("Files")
            }
        }
        .lineLimit(1)
        .navigationTitle(Text("Asset"))
        .navigationBarTitleDisplayMode(.large)
        .fileImporter(isPresented: $assetViewModel.isFileImporterPresented, allowedContentTypes: [.dat], allowsMultipleSelection: true) { result in
            do {
                try assetViewModel.importLocalFiles(urls: try result.get())
                MGNotification.send(title: "", subtitle: "", body: "Asset imported successfully")
            } catch {
                MGNotification.send(title: "", subtitle: "", body: "Asset imported failed, Reason: \(error.localizedDescription)")
            }
        }
        .toolbar {
            Button {
                assetViewModel.isFileImporterPresented.toggle()
            } label: {
                Image(systemName: "plus")
                    .fontWeight(.medium)
            }
        }
    }
}
