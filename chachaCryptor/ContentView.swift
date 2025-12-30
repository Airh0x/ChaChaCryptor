//  Prerequisites:
//  1. Add CryptoSwift via Swift Package Manager.
//     https://github.com/CryptoSwift/CryptoSwift
//  2. In your project's Info.plist, add "Privacy - Face ID Usage Description".
//

import SwiftUI
import UniformTypeIdentifiers

// MARK: - ContentView
struct ContentView: View {
    @StateObject private var cryptoManager = CryptoManager()
    @Environment(\.scenePhase) private var scenePhase
    
    @State private var isShowingBlur = false
    @State private var isShowingResetAlert = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 60))
                    .foregroundColor(.accentColor)
                
                Text("ChaChaCryptor")
                    .font(.largeTitle).bold()
                
                Text("Files are protected by a hardware-bound key in the Secure Enclave.")
                    .font(.subheadline)
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                Text("IMPORTANT: Files encrypted on this device can only be decrypted on this device. They cannot be recovered if you switch to a new device or perform a factory reset.")
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(8)

                VStack(alignment: .leading, spacing: 8) {
                    Text("Encryption Algorithm")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    
                    Picker("Algorithm", selection: $cryptoManager.selectedAlgorithm) {
                        ForEach(EncryptionAlgorithm.allCases, id: \.self) { algorithm in
                            Text(algorithm.displayName).tag(algorithm)
                        }
                    }
                    .pickerStyle(.segmented)
                }
                .padding(.horizontal)

                Spacer()
                
                HStack(spacing: 20) {
                    Button {
                        cryptoManager.prepareForImport(mode: .encrypt)
                    } label: {
                        Label("Encrypt File", systemImage: "lock.fill")
                    }
                    .buttonStyle(MyButtonStyle(color: .accentColor))

                    Button {
                        cryptoManager.prepareForImport(mode: .decrypt)
                    } label: {
                        Label("Decrypt File", systemImage: "lock.open.fill")
                    }
                    .buttonStyle(MyButtonStyle(color: .green))
                }
                
                List {
                    Section(header: Text("Logs")) {
                        ForEach(Array(cryptoManager.logMessages.enumerated()), id: \.offset) { _, message in
                            Text(message).font(.footnote).textSelection(.enabled)
                        }
                    }
                }
                .listStyle(.insetGrouped)
                .frame(maxHeight: 250)
                
                VStack(alignment: .leading, spacing: 8) {
                    Text("Danger Zone")
                        .font(.caption)
                        .foregroundColor(.red)
                        .padding(.horizontal)
                    
                    Button {
                        isShowingResetAlert = true
                    } label: {
                        Label("Reset Master Key", systemImage: "trash.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .padding(.horizontal)
                }

            }
            .padding()
            .navigationTitle("Secure your Files")
            .navigationBarTitleDisplayMode(.inline)
            .blur(radius: isShowingBlur ? 15 : 0)
            .onChange(of: scenePhase) { _, newPhase in
                isShowingBlur = newPhase != .active
            }
            .fileImporter(isPresented: $cryptoManager.isImporting, allowedContentTypes: [UTType.data]) { result in
                Task { await cryptoManager.processFile(result: result) }
            }
            .alert("Are you sure?", isPresented: $isShowingResetAlert) {
                Button("Delete Key", role: .destructive) {
                    Task { await cryptoManager.resetMasterKey() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("If you reset the master key, all previously encrypted files will be permanently unreadable. This action cannot be undone.")
            }
        }
    }
}
