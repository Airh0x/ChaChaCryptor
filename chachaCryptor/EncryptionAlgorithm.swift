//
//  EncryptionAlgorithm.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

enum EncryptionAlgorithm: UInt8, CaseIterable {
    case aes256GCM = 0
    case chaCha20Poly1305 = 1
    case xchaCha20Poly1305 = 2
    
    nonisolated var displayName: String {
        switch self {
        case .aes256GCM: return "AES-256-GCM"
        case .chaCha20Poly1305: return "ChaCha20-Poly1305"
        case .xchaCha20Poly1305: return "XChaCha20-Poly1305"
        }
    }
    
    nonisolated var nonceSize: Int {
        switch self {
        case .aes256GCM: return 12
        case .chaCha20Poly1305: return 12
        case .xchaCha20Poly1305: return 24
        }
    }
    
    nonisolated var tagSize: Int {
        // All algorithms use 16-byte tags
        return 16
    }
}

