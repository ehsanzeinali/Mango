import SwiftUI

struct MGLogSettingView: View {
    
    @ObservedObject private var logViewModel: MGConfigurationPersistentViewModel<MGConfiguration.Log>
    
    init(logViewModel: MGConfigurationPersistentViewModel<MGConfiguration.Log>) {
        self._logViewModel = ObservedObject(initialValue: logViewModel)
    }
    
    var body: some View {
        Form {
            Section {
                Picker(selection: $logViewModel.model.errorLogSeverity) {
                    ForEach(MGConfiguration.Log.Severity.allCases) { severity in
                        Text(severity.description)
                    }
                } label: {
                    Text("Level")
                }
            } header: {
                Text("Error")
            }
            Section {
                Toggle("Access Log", isOn: $logViewModel.model.accessLogEnabled)
                Toggle("DNS Log", isOn: $logViewModel.model.dnsLogEnabled)
            } header: {
                Text("Other")
            }
        }
        .navigationTitle(Text("Log"))
        .navigationBarTitleDisplayMode(.large)
        .onDisappear {
            self.logViewModel.save()
        }
    }
}
