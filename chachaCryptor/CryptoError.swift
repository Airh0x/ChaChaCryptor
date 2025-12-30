//
//  CryptoError.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import Foundation

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

