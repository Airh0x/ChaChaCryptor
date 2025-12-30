//
//  SecureEnclaveManager.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import Foundation
import Security
import CryptoKit
import LocalAuthentication

class SecureEnclaveManager {
    // Use actual bundle identifier for key tag to ensure uniqueness and prevent conflicts
    // Bundle ID: jp.Guard.chachaCryptor
    private let keyTag = "jp.Guard.chachaCryptor.masterKey.v21".data(using: .utf8)!

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

