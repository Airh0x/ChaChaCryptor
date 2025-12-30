//
//  CryptoManager.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import SwiftUI
import Combine
import Foundation
import UIKit
import LocalAuthentication
import UniformTypeIdentifiers

@MainActor
class CryptoManager: ObservableObject {
    @Published var logMessages: [String] = ["Please select an operation to begin."]
    @Published var isImporting = false
    @Published var selectedAlgorithm: EncryptionAlgorithm = .chaCha20Poly1305
    
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
            let algorithmForTask = self.selectedAlgorithm
            let algorithmNonceSize = algorithmForTask.nonceSize
            
            log("🔐 Using algorithm: \(algorithmForTask.displayName)")
            
            try await Task.detached {
                // Define constants here, inside the nonisolated context, to prevent sharing issues.
                // Nonce and tag sizes are now determined by the algorithm itself
                let bufferSize = EncryptionService.defaultBufferSize
                
                switch modeForTask {
                case .encrypt:
                    try EncryptionService.encryptStream(masterKey: masterKey, inputStream: inputStream, outputStream: outputStream, algorithm: algorithmForTask, nonceSize: algorithmNonceSize, bufferSize: bufferSize)
                case .decrypt:
                    // Algorithm will be determined from file format
                    try EncryptionService.decryptStream(masterKey: masterKey, inputStream: inputStream, outputStream: outputStream, bufferSize: bufferSize)
                }
            }

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

    private func log(_ message: String) {
        print(message)
        logMessages.append(message)
    }
    
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

