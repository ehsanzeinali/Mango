import SwiftUI

struct MGDisclosureGroup<Label: View, Content: View>: View {
    
    @State private var isExpanded: Bool = false
    @Binding private var isExpanded__: Bool
    
    private let label: Label
    private let content: Content
    
    
    init(isExpanded: Binding<Bool>, @ViewBuilder content: () -> Content, @ViewBuilder label: () -> Label) {
        self._isExpanded = State(initialValue: isExpanded.wrappedValue)
        self._isExpanded__ = isExpanded
        self.content = content()
        self.label = label()
    }
    
    init(@ViewBuilder content: () -> Content, @ViewBuilder label: () -> Label) {
        self.content = content()
        self.label = label()
        self._isExpanded__ = Binding(get: { false }, set: { _ in })
    }
    
    var body: some View {
        Group {
            LabeledContent {
                Button {
                    withAnimation {
                        self.isExpanded.toggle()
                    }
                } label: {
                    Image(systemName: "chevron.right")
                        .fixedSize()
                        .font(.caption2)
                        .fontWeight(.bold)
                        .rotationEffect(self.isExpanded ? Angle(degrees: 90) : Angle(degrees: 0), anchor: .center)
                }
            } label: {
                self.label
            }
            if self.isExpanded {
                self.content
            }
        }
        .onChange(of: isExpanded, perform: { isExpanded__ = $0 })
    }
}
