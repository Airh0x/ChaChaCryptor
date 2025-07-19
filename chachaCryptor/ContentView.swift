//  Prerequisites:
//  1. Add CryptoSwift via Swift Package Manager.
//     https://github.com/CryptoSwift/CryptoSwift
//  2. In your project's Info.plist, add "Privacy - Face ID Usage Description".
//

import SwiftUI
import Combine
import Foundation
import UIKit
import Security
import CryptoKit
import CryptoSwift
import LocalAuthentication
import UniformTypeIdentifiers

// MARK: - CryptoError
enum CryptoError: Error, LocalizedError {
    case secureEnclaveUnavailable
    case keyGenerationFailed(String)
    case keyDerivationFailed
    case encryptionFailed(String)
    case decryptionFailed(String)
    case invalidFileFormat(String)
    case streamError(String)
    case authenticationFailed

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available on this device."
        case .keyGenerationFailed(let reason):
            return "Failed to generate the master key: \(reason)"
        case .keyDerivationFailed:
            return "Failed to derive the file key."
        case .encryptionFailed(let reason):
            return "Encryption failed: \(reason)"
        case .decryptionFailed(let reason):
            return "Decryption failed: \(reason)"
        case .invalidFileFormat(let reason):
            return "Invalid file format: \(reason)"
        case .streamError(let reason):
            return "File stream error: \(reason)"
        case .authenticationFailed:
            return "Authentication failed or was canceled."
        }
    }
}


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
                
                Section(header: Text("Danger Zone").font(.caption).foregroundColor(.red)) {
                    Button {
                        isShowingResetAlert = true
                    } label: {
                        Label("Reset Master Key", systemImage: "trash.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                }
                .padding(.horizontal)

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

// MARK: - CryptoManager
@MainActor
class CryptoManager: ObservableObject {
    @Published var logMessages: [String] = ["Please select an operation to begin."]
    @Published var isImporting = false
    
    private let enclaveManager = SecureEnclaveManager()
    private var currentMode: Mode = .encrypt
    private var exportDelegateHolder: ExportDelegate?

    enum Mode { case encrypt, decrypt }

    func prepareForImport(mode: Mode) {
        self.currentMode = mode
        self.isImporting = true
    }

    func resetMasterKey() async {
        log("🔥 Resetting master key...")

        // 1. First, always request authentication directly.
        let context = LAContext()
        let reason = "Authentication is required to delete the master key."

        do {
            // This will always show the Face ID / Touch ID prompt, regardless of key presence.
            let authenticated = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)

            // 2. Only if authentication succeeds, proceed with deletion.
            if authenticated {
                log("🔑 Authentication successful. Proceeding with deletion...")
                try enclaveManager.deleteKey() // Deletes the key if it exists.
                log("✅ Master key has been deleted (if it existed).")
                log("ℹ️ A new key will be generated on the next operation.")
            } else {
                // This case is rare with .deviceOwnerAuthentication but included for completeness.
                 log("❌ Authentication not granted. Key reset canceled.")
            }

        } catch {
            // This catches failures, such as the user tapping "Cancel".
            log("❌ Authentication failed or was canceled. Key reset canceled.")
        }
    }
    
    func processFile(result: Result<URL, Error>) async {
        logMessages = []
        
        do {
            let sourceURL = try result.get()
            log("📁 Selected file: \(sourceURL.lastPathComponent)")
            
            let newName = getNewFilename(original: sourceURL.lastPathComponent)
            let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(newName)

            guard sourceURL.startAccessingSecurityScopedResource() else {
                throw CryptoError.streamError("Could not access security-scoped resource.")
            }
            defer { sourceURL.stopAccessingSecurityScopedResource() }

            guard let inputStream = InputStream(url: sourceURL),
                  let outputStream = OutputStream(url: tempURL, append: false) else {
                throw CryptoError.streamError("Could not create file streams.")
            }
            
            inputStream.open()
            outputStream.open()
            defer {
                inputStream.close()
                outputStream.close()
                try? FileManager.default.removeItem(at: tempURL)
            }
            
            log("🔑 Retrieving master key from Secure Enclave...")
            let masterKey = try enclaveManager.getKey()
            log("🔑 Master key reference obtained.")
            
            let modeForTask = self.currentMode
            
            try await Task.detached {
                // Define constants here, inside the nonisolated context, to prevent sharing issues.
                let nonceSize = 12
                let tagSize = 16
                let bufferSize = 4096
                
                switch modeForTask {
                case .encrypt:
                    try Self.encryptStream(masterKey: masterKey, inputStream: inputStream, outputStream: outputStream, nonceSize: nonceSize, bufferSize: bufferSize)
                case .decrypt:
                    try Self.decryptStream(masterKey: masterKey, inputStream: inputStream, outputStream: outputStream, nonceSize: nonceSize, tagSize: tagSize, bufferSize: bufferSize)
                }
            }.value

            switch self.currentMode {
            case .encrypt: log("✅ Encryption successful!")
            case .decrypt: log("✅ Decryption successful!")
            }

            let finalURL = try await exportFile(url: tempURL)
            log("💾 File saved to: \(finalURL.path(percentEncoded: false))")
            
        } catch let error as LocalizedError {
            log("❌ Error: \(error.localizedDescription)")
        } catch {
            log("❌ An unexpected error occurred: \(error.localizedDescription)")
        }
    }

    @MainActor
    private func log(_ message: String) {
        print(message)
        logMessages.append(message)
    }
    
    nonisolated private static func encryptStream(masterKey: SecKey, inputStream: InputStream, outputStream: OutputStream, nonceSize: Int, bufferSize: Int) throws {
        let fileKey = SymmetricKey(size: .bits256)
        
        guard let masterPublicKey = SecKeyCopyPublicKey(masterKey) else {
            throw CryptoError.keyGenerationFailed("Could not get public key from master key.")
        }
        
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        var error: Unmanaged<CFError>?
        let fileKeyData = fileKey.withUnsafeBytes { Data($0) }
        guard let encryptedFileKey = SecKeyCreateEncryptedData(masterPublicKey, algorithm, fileKeyData as CFData, &error) as? Data else {
            throw error?.takeRetainedValue() as? Error ?? CryptoError.encryptionFailed("Could not encrypt file key.")
        }
        
        let nonceBytes = AES.randomIV(nonceSize)
        
        let gcm = GCM(iv: nonceBytes, mode: .detached)
        let aes = try AES(key: Array(fileKeyData), blockMode: gcm, padding: .noPadding)
        var encryptor = try aes.makeEncryptor()
        
        var ciphertext = Data()
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(&buffer, maxLength: buffer.count)
            if bytesRead < 0 { throw CryptoError.streamError("Input stream read error.") }
            if bytesRead == 0 { break }
            
            let chunk = try encryptor.update(withBytes: Array(buffer[0..<bytesRead]))
            ciphertext.append(contentsOf: chunk)
        }
        
        let finalChunk = try encryptor.finish()
        ciphertext.append(contentsOf: finalChunk)
        
        guard let tag = gcm.authenticationTag else {
            throw CryptoError.encryptionFailed("Could not get authentication tag.")
        }

        var encryptedKeyLength = UInt32(encryptedFileKey.count).bigEndian
        _ = try outputStream.write(data: Data(bytes: &encryptedKeyLength, count: MemoryLayout<UInt32>.size))
        _ = try outputStream.write(data: encryptedFileKey)
        _ = try outputStream.write(data: Data(nonceBytes))
        _ = try outputStream.write(data: Data(tag))
        _ = try outputStream.write(data: ciphertext)
    }

    nonisolated private static func decryptStream(masterKey: SecKey, inputStream: InputStream, outputStream: OutputStream, nonceSize: Int, tagSize: Int, bufferSize: Int) throws {
        let keyLengthData = try inputStream.readBytes(count: MemoryLayout<UInt32>.size)
        let keyLength = keyLengthData.withUnsafeBytes { $0.load(as: UInt32.self) }.bigEndian
        
        let encryptedFileKey = try inputStream.readBytes(count: Int(keyLength))
        let nonceBytes = try inputStream.readBytes(count: nonceSize)
        let tagBytes = try inputStream.readBytes(count: tagSize)
        
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        var error: Unmanaged<CFError>?
        guard let decryptedFileKeyData = SecKeyCreateDecryptedData(masterKey, algorithm, Data(encryptedFileKey) as CFData, &error) as? Data else {
            throw error?.takeRetainedValue() as? Error ?? CryptoError.decryptionFailed("Could not decrypt file key. User may have cancelled authentication.")
        }
        
        let gcm = GCM(iv: nonceBytes, authenticationTag: tagBytes)
        let aes = try AES(key: Array(decryptedFileKeyData), blockMode: gcm, padding: .noPadding)
        var decryptor = try aes.makeDecryptor()

        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(&buffer, maxLength: buffer.count)
            if bytesRead < 0 { throw CryptoError.streamError("Read error") }
            if bytesRead == 0 { break }
            
            let plaintextChunk = try decryptor.update(withBytes: Array(buffer[0..<bytesRead]))
            _ = try outputStream.write(data: Data(plaintextChunk))
        }
        
        let finalPlaintextChunk = try decryptor.finish()
        _ = try outputStream.write(data: Data(finalPlaintextChunk))
    }
    
    @MainActor
    private func exportFile(url: URL) async throws -> URL {
        let controller = UIDocumentPickerViewController(forExporting: [url], asCopy: true)
        controller.shouldShowFileExtensions = true

        guard let window = (UIApplication.shared.connectedScenes.first as? UIWindowScene)?.windows.first else {
            throw CryptoError.streamError("Could not find active window scene.")
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            self.exportDelegateHolder = ExportDelegate(
                onSuccess: { url in continuation.resume(returning: url) },
                onFailure: { error in continuation.resume(throwing: error) }
            )
            controller.delegate = self.exportDelegateHolder
            window.rootViewController?.present(controller, animated: true)
        }
    }
    
    private func getNewFilename(original: String) -> String {
        switch currentMode {
        case .encrypt: return original + ".enc"
        case .decrypt: return original.hasSuffix(".enc") ? String(original.dropLast(4)) : "decrypted_" + original
        }
    }
}


// MARK: - SecureEnclaveManager
class SecureEnclaveManager {
    private let keyTag = "com.example.EnclaveGuard.masterKey.v21".data(using: .utf8)!

    func getKey() throws -> SecKey {
        do {
            return try loadKey()
        } catch {
            return try generateAndStoreKey()
        }
    }
    
    func deleteKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        let status = SecItemDelete(query as CFDictionary)
        // It's not an error if the key doesn't exist to be deleted.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CryptoError.keyGenerationFailed("Could not delete existing key.")
        }
    }

    private func generateAndStoreKey() throws -> SecKey {
        guard SecureEnclave.isAvailable else { throw CryptoError.secureEnclaveUnavailable }
        try? deleteKey()
        
        // Add .userPresence flag to require authentication (Face ID, Touch ID, or passcode) for key usage.
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence]
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            nil
        )!
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: accessControl
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    private func loadKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecReturnRef as String: true,
            // Provide an LAContext to allow the system to trigger an authentication prompt.
            kSecUseAuthenticationContext as String: LAContext()
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess, let item = item else {
            throw CryptoError.keyGenerationFailed("Key not found or user cancelled auth.")
        }
        // If successful, a force cast is safe here based on the query.
        return item as! SecKey
    }
}


// MARK: - Helper Views, Types & Extensions
class ExportDelegate: NSObject, UIDocumentPickerDelegate {
    let onSuccess: (URL) -> Void
    let onFailure: (Error) -> Void

    init(onSuccess: @escaping (URL) -> Void, onFailure: @escaping (Error) -> Void) {
        self.onSuccess = onSuccess
        self.onFailure = onFailure
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first else {
            onFailure(CryptoError.streamError("Export was cancelled or failed."))
            return
        }
        onSuccess(url)
    }
    
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        onFailure(CryptoError.streamError("Export was cancelled."))
    }
}

nonisolated extension OutputStream {
    func write(data: Data) throws -> Int {
        try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Int in
            guard let baseAddress = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            let bytesWritten = self.write(baseAddress, maxLength: data.count)
            if bytesWritten < 0 { throw CryptoError.streamError("Write failed.") }
            return bytesWritten
        }
    }
}

nonisolated extension InputStream {
    func readBytes(count: Int) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        let bytesRead = self.read(&buffer, maxLength: count)
        if bytesRead < count { throw CryptoError.streamError("Could not read required number of bytes. Expected \(count), got \(bytesRead).") }
        return buffer
    }
}

struct MyButtonStyle: ButtonStyle {
    var color: Color
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 20).padding(.vertical, 12)
            .frame(maxWidth: .infinity)
            .background(color).foregroundColor(.white)
            .clipShape(Capsule())
            .scaleEffect(configuration.isPressed ? 0.97 : 1.0)
            .animation(.easeOut(duration: 0.2), value: configuration.isPressed)
    }
}
