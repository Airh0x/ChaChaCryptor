//
//  EncryptionHelpers.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import Foundation
import Security
import CryptoSwift

struct EncryptionHelpers {
    /// Generates Poly1305 key from ChaCha20 keystream (RFC 8439 style)
    /// Uses ChaCha20 with counter 0 to generate first 32 bytes as Poly1305 key
    nonisolated static func generatePoly1305Key(key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        var poly1305Key: [UInt8] = []
        var keystreamForPolyKey: [UInt8] = []
        
        defer {
            // Securely zero out temporary key material
            keystreamForPolyKey.secureZero()
        }
        
        let poly1305KeySize = 32
        let tempChacha = try ChaCha20(key: key, iv: nonce)
        let zeroBlock = [UInt8](repeating: 0, count: poly1305KeySize)
        keystreamForPolyKey = try tempChacha.encrypt(zeroBlock)
        poly1305Key = Array(keystreamForPolyKey[0..<poly1305KeySize])
        
        return poly1305Key
    }
    
    /// Reads all data from input stream into a Data object
    nonisolated static func readAllData(from inputStream: InputStream, bufferSize: Int) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(&buffer, maxLength: buffer.count)
            if bytesRead < 0 {
                throw CryptoError.streamError("Input stream read error.")
            }
            if bytesRead == 0 {
                break
            }
            data.append(contentsOf: buffer[0..<bytesRead])
        }
        
        return data
    }
    
    /// Decrypts file key using master key
    nonisolated static func decryptFileKey(
        encryptedFileKey: [UInt8],
        masterKey: SecKey
    ) throws -> Data {
        // Validate encrypted key length (should be reasonable size)
        guard encryptedFileKey.count > 0 && encryptedFileKey.count < 1024 else {
            throw CryptoError.decryptionFailed("Invalid encrypted file key length.")
        }
        
        let keyAlgorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        var error: Unmanaged<CFError>?
        guard let decryptedFileKeyData = SecKeyCreateDecryptedData(
            masterKey,
            keyAlgorithm,
            Data(encryptedFileKey) as CFData,
            &error
        ) as? Data else {
            throw error?.takeRetainedValue() as? Error
                ?? CryptoError.decryptionFailed("Could not decrypt file key. User may have cancelled authentication.")
        }
        
        // Validate decrypted key length (must be 32 bytes for 256-bit keys)
        guard SecurityHelpers.validateKeyLength(decryptedFileKeyData, expectedLength: 32) else {
            throw CryptoError.decryptionFailed("Invalid decrypted file key length.")
        }
        
        return decryptedFileKeyData
    }
    
    /// Generates a random nonce of specified size
    nonisolated static func generateRandomNonce(size: Int) throws -> [UInt8] {
        var nonceBytes = [UInt8](repeating: 0, count: size)
        let status = SecRandomCopyBytes(kSecRandomDefault, size, &nonceBytes)
        guard status == errSecSuccess else {
            throw CryptoError.encryptionFailed("Could not generate random nonce.")
        }
        return nonceBytes
    }
    
    /// Verifies Poly1305 authentication tag using constant-time comparison
    /// This prevents timing attacks that could leak information about the tag
    nonisolated static func verifyPoly1305Tag(
        ciphertext: [UInt8],
        expectedTag: [UInt8],
        poly1305Key: [UInt8]
    ) throws {
        // Validate input lengths
        guard expectedTag.count == 16 else {
            throw CryptoError.decryptionFailed("Invalid authentication tag length.")
        }
        guard poly1305Key.count == 32 else {
            throw CryptoError.decryptionFailed("Invalid Poly1305 key length.")
        }
        
        let poly1305 = Poly1305(key: poly1305Key)
        let calculatedTag = try poly1305.authenticate(ciphertext)
        
        // Use constant-time comparison to prevent timing attacks
        guard SecurityHelpers.constantTimeCompare(Data(calculatedTag), Data(expectedTag)) else {
            throw CryptoError.decryptionFailed("Authentication tag verification failed. File may be corrupted or tampered.")
        }
    }
}

