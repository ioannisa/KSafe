import SwiftUI
import ksafe

struct ContentView: View {
    @StateObject private var viewModel = KSafeViewModel()
    @State private var inputText = ""
    
    var body: some View {
        VStack(spacing: 20) {
            Text("KSafe Flow Test")
                .font(.largeTitle)
                .padding()
            
            if let errorMessage = viewModel.errorMessage {
                Text("Error: \(errorMessage)")
                    .foregroundColor(.red)
                    .padding()
            }
            
            VStack(alignment: .leading, spacing: 10) {
                Text("Current Value from Flow:")
                    .font(.headline)
                
                Text(viewModel.currentValue)
                    .font(.system(.body, design: .monospaced))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(8)
            }
            .padding(.horizontal)
            
            VStack(spacing: 10) {
                TextField("Enter new value", text: $inputText)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding(.horizontal)
                
                Button(action: {
                    viewModel.updateValue(inputText)
                    inputText = ""
                }) {
                    Text("Update Value")
                        .foregroundColor(.white)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Color.blue)
                        .cornerRadius(8)
                }
                .padding(.horizontal)
                
                Button(action: {
                    viewModel.updateWithRandomString()
                }) {
                    Text("Set Random Value")
                        .foregroundColor(.white)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Color.green)
                        .cornerRadius(8)
                }
                .padding(.horizontal)
            }
            
            Spacer()
            
            Text("Last Updated: \(viewModel.lastUpdated)")
                .font(.caption)
                .foregroundColor(.gray)
                .padding()
        }
        .onAppear {
            viewModel.initialize()
        }
    }
}

class KSafeViewModel: ObservableObject {
    @Published var currentValue: String = "No value yet"
    @Published var lastUpdated: String = "Never"
    @Published var errorMessage: String? = nil
    
    // Use a simple in-memory storage to simulate Flow behavior
    private var memoryStorage: [String: String] = [:]
    private var pollingTimer: Timer?
    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()
    
    init() {
        // Initialize with a default value
        memoryStorage["test"] = "Initial Value"
    }
    
    func initialize() {
        // Start with simple memory-based simulation
        startPolling()
    }
    
    func startPolling() {
        // Initial read
        updateCurrentValue()
        
        // Start polling every 0.5 seconds to simulate Flow
        pollingTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            self.updateCurrentValue()
        }
    }
    
    private func updateCurrentValue() {
        // Read from memory storage (simulating Flow emission)
        if let value = memoryStorage["test"] {
            if value != currentValue {
                DispatchQueue.main.async {
                    self.currentValue = value
                    self.lastUpdated = self.dateFormatter.string(from: Date())
                    print("Value updated to: \(value)")
                }
            }
        }
    }
    
    func updateValue(_ newValue: String) {
        // Update memory storage (simulating putDirect)
        memoryStorage["test"] = newValue
        print("Stored value: \(newValue)")
        
        // Immediately update the UI
        updateCurrentValue()
    }
    
    func updateWithRandomString() {
        let randomString = "Random-\(UUID().uuidString.prefix(8))"
        updateValue(randomString)
    }
    
    
    deinit {
        pollingTimer?.invalidate()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}