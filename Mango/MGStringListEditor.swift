import SwiftUI

struct MGStringListEditor: View {
    
    @Binding var strings: [String]
    
    let placeholder: String?
    
    @State private var value: String = ""
    
    var body: some View {
        ForEach(self.strings, id: \.self) { string in
            Text(string)
        }
        .onMove { from, to in
            self.strings.move(fromOffsets: from, toOffset: to)
        }
        .onDelete { offsets in
            self.strings.remove(atOffsets: offsets)
        }
        HStack(spacing: 16) {
            Image(systemName: "plus.circle.fill")
                .resizable()
                .frame(width: 18, height: 18)
                .foregroundColor(.green)
                .background(Circle().foregroundColor(.white))
            TextField(placeholder ?? "Input new element here", text: $value)
                .onSubmit {
                    let temp = self.value.trimmingCharacters(in: .whitespacesAndNewlines)
                    DispatchQueue.main.async {
                        self.value = ""
                    }
                    guard !temp.isEmpty else {
                        return
                    }
                    guard !self.strings.contains(where: { $0 == temp }) else {
                        return
                    }
                    self.strings.append(temp)
                }
                .multilineTextAlignment(.leading)
        }
        .padding(.leading, 2)
    }
}
