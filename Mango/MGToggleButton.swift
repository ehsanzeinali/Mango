import SwiftUI

struct MGToggleButton: View {
    
    @Environment(\.colorScheme) private var colorScheme
    
    @State private var localState: Bool = false
    
    init(title: String, isOn: Binding<Bool>) {
        self.title = title
        self.isOn = isOn
        self._localState = State(initialValue: isOn.wrappedValue)
    }
    
    private let title: String
    private let isOn: Binding<Bool>
    
    var body: some View {
        HStack(spacing: 0) {
            Text("-")
                .foregroundColor(.clear)
            Text(title)
            Text("-")
                .foregroundColor(.clear)
        }
        .foregroundColor(.accentColor)
        .padding(.vertical, 8)
        .background(self.localState ? .accentColor.opacity(0.2) : self.backgroundColor)
        .cornerRadius(6)
        .onTapGesture {
            isOn.wrappedValue.toggle()
        }
        .onChange(of: isOn.wrappedValue) { newValue in
            withAnimation(.easeIn(duration: 0.1)) {
                self.localState = newValue
            }
        }
    }
    
    private var backgroundColor: Color {
        switch colorScheme {
        case .light:
            return .gray.opacity(0.1)
        case .dark:
            return .white.opacity(0.1)
        @unknown default:
            return .gray.opacity(0.1)
        }
    }
}
