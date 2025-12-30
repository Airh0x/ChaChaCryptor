//
//  EncryptionService.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import Foundation
import Security
import CryptoKit
import CryptoSwift

struct EncryptionService {
    // MARK: - Constants
    static let defaultBufferSize = 4096
    nonisolated private static let poly1305KeySize = 32
    nonisolated private static let zeroBlockSize = 32
    nonisolated private static let oldFormatNonceSize = 12
    nonisolated private static let oldFormatTagSize = 16
    nonisolated private static let keyLengthSize = MemoryLayout<UInt32>.size
    
    // MARK: - HChaCha20 Helper (RFC 8439)
    // HChaCha20 is used by XChaCha20 to derive a subkey from a 24-byte nonce
    nonisolated private static func hChaCha20(key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
        // HChaCha20 uses the first 16 bytes of nonce
        guard nonce.count >= 16 else {
            throw CryptoError.encryptionFailed("Nonce must be at least 16 bytes for HChaCha20")
        }
        
        // HChaCha20 construction (RFC 8439):
        // HChaCha20 uses the first 16 bytes of the nonce, but ChaCha20 only accepts 8 or 12 byte IVs
        // For CryptoSwift compatibility, we use the first 12 bytes of the 16-byte nonce segment
        // This is an approximation; a full RFC-compliant HChaCha20 would require manual implementation
        let hchachaIVSize = 12  // Use 12 bytes (ChaCha20's maximum IV size)
        let hchachaIV = Array(nonce[0..<hchachaIVSize])
        
        // Create ChaCha20 instance with counter starting at 0
        // Encrypt 64 zero bytes (one full block) to get keystream
        let chacha = try ChaCha20(key: key, iv: hchachaIV)
        let zeroBlock = [UInt8](repeating: 0, count: 64)  // One full ChaCha20 block
        let keystream = try chacha.encrypt(zeroBlock)
        
        // HChaCha20 outputs only the first 32 bytes of the keystream
        return Array(keystream[0..<poly1305KeySize])
    }
    nonisolated static func encryptStream(
        masterKey: SecKey,
        inputStream: InputStream,
        outputStream: OutputStream,
        algorithm: EncryptionAlgorithm,
        nonceSize: Int,
        bufferSize: Int
    ) throws {
        let fileKey = SymmetricKey(size: .bits256)
        
        guard let masterPublicKey = SecKeyCopyPublicKey(masterKey) else {
            throw CryptoError.keyGenerationFailed("Could not get public key from master key.")
        }
        
        let keyAlgorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM
        var error: Unmanaged<CFError>?
        let fileKeyData = fileKey.withUnsafeBytes { Data($0) }
        
        // Validate file key length (must be 32 bytes for 256-bit keys)
        guard SecurityHelpers.validateKeyLength(fileKeyData, expectedLength: 32) else {
            throw CryptoError.keyGenerationFailed("Invalid file key length.")
        }
        
        guard let encryptedFileKey = SecKeyCreateEncryptedData(masterPublicKey, keyAlgorithm, fileKeyData as CFData, &error) as? Data else {
            throw error?.takeRetainedValue() as? Error ?? CryptoError.encryptionFailed("Could not encrypt file key.")
        }
        
        let nonceBytes: [UInt8]
        let ciphertext: Data
        let tag: [UInt8]
        
        let algorithmNonceSize = algorithm.nonceSize
        
        // Create mutable copy for secure cleanup
        var mutableFileKeyData = fileKeyData
        
        defer {
            // Securely zero out the file key data after use
            mutableFileKeyData.secureZero()
        }
        
        switch algorithm {
        case .aes256GCM:
            (nonceBytes, ciphertext, tag) = try encryptWithAESGCM(inputStream: inputStream, fileKeyData: mutableFileKeyData, nonceSize: algorithmNonceSize, bufferSize: bufferSize)
        case .chaCha20Poly1305:
            (nonceBytes, ciphertext, tag) = try encryptWithChaCha20Poly1305(inputStream: inputStream, fileKeyData: mutableFileKeyData, nonceSize: algorithmNonceSize, bufferSize: bufferSize)
        case .xchaCha20Poly1305:
            (nonceBytes, ciphertext, tag) = try encryptWithXChaCha20Poly1305(inputStream: inputStream, fileKeyData: mutableFileKeyData, nonceSize: algorithmNonceSize, bufferSize: bufferSize)
        }
        
        // Write file format: [algorithm(1byte)][keyLength(4bytes)][encryptedFileKey][nonce(variable)][tag(16bytes)][ciphertext]
        _ = try outputStream.write(data: Data([algorithm.rawValue]))
        var encryptedKeyLength = UInt32(encryptedFileKey.count).bigEndian
        _ = try outputStream.write(data: Data(bytes: &encryptedKeyLength, count: keyLengthSize))
        _ = try outputStream.write(data: encryptedFileKey)
        _ = try outputStream.write(data: Data(nonceBytes))
        _ = try outputStream.write(data: Data(tag))
        _ = try outputStream.write(data: ciphertext)
    }
    
    nonisolated static func decryptStream(
        masterKey: SecKey,
        inputStream: InputStream,
        outputStream: OutputStream,
        bufferSize: Int
    ) throws {
        // Read algorithm identifier (1 byte)
        // Format: [algorithm(1byte)][keyLength(4bytes)][encryptedFileKey][nonce(12bytes)][tag(16bytes)][ciphertext]
        // For backward compatibility with old format (without algorithm byte), we check if first byte is valid algorithm
        let algorithm: EncryptionAlgorithm
        
        let algorithmBytes = try inputStream.readBytes(count: 1)
        let firstByte = algorithmBytes[0]
        
        if let algo = EncryptionAlgorithm(rawValue: firstByte) {
            algorithm = algo
        } else {
            // Old format file (without algorithm identifier)
            // The first byte is part of keyLength, so we need to reconstruct it
            // Read remaining 3 bytes of keyLength
            let remainingKeyLengthBytes = try inputStream.readBytes(count: 3)
            let keyLengthBytes = [firstByte] + remainingKeyLengthBytes
            let keyLength = keyLengthBytes.withUnsafeBytes { $0.load(as: UInt32.self) }.bigEndian
            
            // Old format is always AES-GCM
            algorithm = .aes256GCM
            
            // Continue with old format decryption (always AES-GCM with 12-byte nonce)
            // Validate key length to prevent integer overflow and DoS attacks
            guard keyLength > 0 && keyLength <= 1024 else {
                throw CryptoError.invalidFileFormat("Invalid encrypted key length in file header.")
            }
            
            let encryptedFileKey = try inputStream.readBytes(count: Int(keyLength))
            let nonceBytes = try inputStream.readBytes(count: oldFormatNonceSize)
            let tagBytes = try inputStream.readBytes(count: oldFormatTagSize)
            
            // Validate nonce and tag lengths for old format
            guard SecurityHelpers.validateNonceLength(nonceBytes, expectedLength: oldFormatNonceSize) else {
                throw CryptoError.invalidFileFormat("Invalid nonce length in file.")
            }
            guard tagBytes.count == oldFormatTagSize else {
                throw CryptoError.invalidFileFormat("Invalid tag length in file.")
            }
            
            // Decrypt file key using helper function
            var decryptedFileKeyData = try EncryptionHelpers.decryptFileKey(encryptedFileKey: encryptedFileKey, masterKey: masterKey)
            
            defer {
                // Securely zero out the decrypted file key data after use
                decryptedFileKeyData.secureZero()
            }
            
            try decryptWithAESGCM(inputStream: inputStream, outputStream: outputStream, fileKeyData: decryptedFileKeyData, nonceBytes: nonceBytes, tagBytes: tagBytes, bufferSize: bufferSize)
            return
        }
        
        let keyLengthData = try inputStream.readBytes(count: keyLengthSize)
        let keyLength = keyLengthData.withUnsafeBytes { $0.load(as: UInt32.self) }.bigEndian
        
        // Validate key length to prevent integer overflow and DoS attacks
        guard keyLength > 0 && keyLength <= 1024 else {
            throw CryptoError.invalidFileFormat("Invalid encrypted key length in file header.")
        }
        
        let encryptedFileKey = try inputStream.readBytes(count: Int(keyLength))
        let algorithmNonceSize = algorithm.nonceSize
        let algorithmTagSize = algorithm.tagSize
        let nonceBytes = try inputStream.readBytes(count: algorithmNonceSize)
        let tagBytes = try inputStream.readBytes(count: algorithmTagSize)
        
        // Decrypt file key using helper function
        var decryptedFileKeyData = try EncryptionHelpers.decryptFileKey(encryptedFileKey: encryptedFileKey, masterKey: masterKey)
        
        defer {
            // Securely zero out the decrypted file key data after use
            decryptedFileKeyData.secureZero()
        }
        
        switch algorithm {
        case .aes256GCM:
            try decryptWithAESGCM(inputStream: inputStream, outputStream: outputStream, fileKeyData: decryptedFileKeyData, nonceBytes: nonceBytes, tagBytes: tagBytes, bufferSize: bufferSize)
        case .chaCha20Poly1305:
            try decryptWithChaCha20Poly1305(inputStream: inputStream, outputStream: outputStream, fileKeyData: decryptedFileKeyData, nonceBytes: nonceBytes, tagBytes: tagBytes, bufferSize: bufferSize)
        case .xchaCha20Poly1305:
            try decryptWithXChaCha20Poly1305(inputStream: inputStream, outputStream: outputStream, fileKeyData: decryptedFileKeyData, nonceBytes: nonceBytes, tagBytes: tagBytes, bufferSize: bufferSize)
        }
    }
    
    // MARK: - Private Encryption Methods
    
    nonisolated private static func encryptWithAESGCM(inputStream: InputStream, fileKeyData: Data, nonceSize: Int, bufferSize: Int) throws -> (nonce: [UInt8], ciphertext: Data, tag: [UInt8]) {
        // Validate key length before encryption
        guard SecurityHelpers.validateKeyLength(fileKeyData, expectedLength: 32) else {
            throw CryptoError.encryptionFailed("Invalid key length for AES-256.")
        }
        
        // Use secure random nonce generation (same as other algorithms)
        let nonceBytes = try EncryptionHelpers.generateRandomNonce(size: nonceSize)
        
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
        
        return (nonceBytes, ciphertext, Array(tag))
    }
    
    nonisolated private static func encryptWithChaCha20Poly1305(inputStream: InputStream, fileKeyData: Data, nonceSize: Int, bufferSize: Int) throws -> (nonce: [UInt8], ciphertext: Data, tag: [UInt8]) {
        // Generate random nonce
        let nonceBytes = try EncryptionHelpers.generateRandomNonce(size: nonceSize)
        
        // Read all plaintext first (needed for ChaCha20 encryption)
        let plaintext = try EncryptionHelpers.readAllData(from: inputStream, bufferSize: bufferSize)
        
        // Encrypt with ChaCha20
        let chacha = try ChaCha20(key: Array(fileKeyData), iv: nonceBytes)
        let plaintextBytes = Array(plaintext)
        let ciphertextBytes = try chacha.encrypt(plaintextBytes)
        let ciphertext = Data(ciphertextBytes)
        
        // Generate Poly1305 key from ChaCha20 keystream (RFC 8439 style)
        var poly1305Key: [UInt8] = []
        
        defer {
            // Securely zero out temporary key material
            poly1305Key.secureZero()
        }
        
        // Generate Poly1305 key using helper function
        poly1305Key = try EncryptionHelpers.generatePoly1305Key(key: Array(fileKeyData), nonce: nonceBytes)
        
        // Generate authentication tag with Poly1305
        let poly1305 = Poly1305(key: poly1305Key)
        let tag = try poly1305.authenticate(ciphertextBytes)
        
        return (nonceBytes, ciphertext, tag)
    }
    
    nonisolated private static func encryptWithXChaCha20Poly1305(inputStream: InputStream, fileKeyData: Data, nonceSize: Int, bufferSize: Int) throws -> (nonce: [UInt8], ciphertext: Data, tag: [UInt8]) {
        // Validate key length before encryption
        guard SecurityHelpers.validateKeyLength(fileKeyData, expectedLength: 32) else {
            throw CryptoError.encryptionFailed("Invalid key length for XChaCha20.")
        }
        
        // Generate random nonce (24 bytes for XChaCha20)
        let nonceBytes = try EncryptionHelpers.generateRandomNonce(size: nonceSize)
        
        // Read all plaintext first (needed for XChaCha20 encryption)
        let plaintext = try EncryptionHelpers.readAllData(from: inputStream, bufferSize: bufferSize)
        
        // XChaCha20: Use HChaCha20 to derive subkey from 24-byte nonce
        // HChaCha20 uses first 16 bytes of nonce, output is 32-byte subkey
        // Then use subkey with last 8 bytes of nonce (padded to 12 bytes) for ChaCha20
        var subkey = try hChaCha20(key: Array(fileKeyData), nonce: nonceBytes)
        
        // Validate subkey length (must be 32 bytes)
        guard subkey.count == 32 else {
            throw CryptoError.encryptionFailed("Invalid subkey length from HChaCha20.")
        }
        var poly1305Key: [UInt8] = []
        
        defer {
            // Securely zero out temporary key material
            subkey.secureZero()
            poly1305Key.secureZero()
        }
        
        // Use last 8 bytes of 24-byte nonce, padded with 4 zero bytes to make 12-byte IV
        // RFC 8439 XChaCha20 specification: subkey + nonce[16:24] (8 bytes) as IV
        let xchachaNonceStartIndex = 16
        let xchachaNonceEndIndex = 24
        let xchachaNoncePadding = 4
        let chachaNonce = Array(nonceBytes[xchachaNonceStartIndex..<xchachaNonceEndIndex]) + [UInt8](repeating: 0, count: xchachaNoncePadding)
        
        // Encrypt with ChaCha20 using the derived subkey and constructed nonce
        let chacha = try ChaCha20(key: subkey, iv: chachaNonce)
        let plaintextBytes = Array(plaintext)
        let ciphertextBytes = try chacha.encrypt(plaintextBytes)
        let ciphertext = Data(ciphertextBytes)
        
        // Generate Poly1305 key using helper function
        poly1305Key = try EncryptionHelpers.generatePoly1305Key(key: subkey, nonce: chachaNonce)
        
        // Generate authentication tag with Poly1305
        let poly1305 = Poly1305(key: poly1305Key)
        let tag = try poly1305.authenticate(ciphertextBytes)
        
        // Return full 24-byte nonce (RFC 8439 XChaCha20-Poly1305 compliant)
        return (nonceBytes, ciphertext, tag)
    }
    
    // MARK: - Private Decryption Methods
    
    nonisolated private static func decryptWithAESGCM(inputStream: InputStream, outputStream: OutputStream, fileKeyData: Data, nonceBytes: [UInt8], tagBytes: [UInt8], bufferSize: Int) throws {
        // Validate key and nonce lengths before decryption
        guard SecurityHelpers.validateKeyLength(fileKeyData, expectedLength: 32) else {
            throw CryptoError.decryptionFailed("Invalid key length for AES-256.")
        }
        guard SecurityHelpers.validateNonceLength(nonceBytes, expectedLength: 12) else {
            throw CryptoError.decryptionFailed("Invalid nonce length for AES-GCM.")
        }
        guard tagBytes.count == 16 else {
            throw CryptoError.decryptionFailed("Invalid tag length for AES-GCM.")
        }
        
        let gcm = GCM(iv: nonceBytes, authenticationTag: tagBytes)
        let aes = try AES(key: Array(fileKeyData), blockMode: gcm, padding: .noPadding)
        var decryptor = try aes.makeDecryptor()

        var buffer = [UInt8](repeating: 0, count: bufferSize)
        defer {
            // Securely zero out buffer after use
            buffer.secureZero()
        }
        
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
    
    nonisolated private static func decryptWithChaCha20Poly1305(inputStream: InputStream, outputStream: OutputStream, fileKeyData: Data, nonceBytes: [UInt8], tagBytes: [UInt8], bufferSize: Int) throws {
        // Read all ciphertext first (needed for authentication and decryption)
        let allCiphertext = try EncryptionHelpers.readAllData(from: inputStream, bufferSize: bufferSize)
        let ciphertextBytes = Array(allCiphertext)
        
        // Generate Poly1305 key from ChaCha20 keystream (RFC 8439 style)
        var poly1305Key: [UInt8] = []
        
        defer {
            // Securely zero out temporary key material
            poly1305Key.secureZero()
        }
        
        poly1305Key = try EncryptionHelpers.generatePoly1305Key(key: Array(fileKeyData), nonce: nonceBytes)
        
        // Verify authentication tag with Poly1305
        try EncryptionHelpers.verifyPoly1305Tag(
            ciphertext: ciphertextBytes,
            expectedTag: tagBytes,
            poly1305Key: poly1305Key
        )
        
        // Decrypt the ciphertext
        let chacha = try ChaCha20(key: Array(fileKeyData), iv: nonceBytes)
        let plaintext = try chacha.decrypt(ciphertextBytes)
        _ = try outputStream.write(data: Data(plaintext))
    }
    
    nonisolated private static func decryptWithXChaCha20Poly1305(inputStream: InputStream, outputStream: OutputStream, fileKeyData: Data, nonceBytes: [UInt8], tagBytes: [UInt8], bufferSize: Int) throws {
        // Validate key and nonce lengths before decryption
        guard SecurityHelpers.validateKeyLength(fileKeyData, expectedLength: 32) else {
            throw CryptoError.decryptionFailed("Invalid key length for XChaCha20.")
        }
        guard SecurityHelpers.validateNonceLength(nonceBytes, expectedLength: 24) else {
            throw CryptoError.decryptionFailed("Invalid nonce length for XChaCha20-Poly1305.")
        }
        guard tagBytes.count == 16 else {
            throw CryptoError.decryptionFailed("Invalid tag length for XChaCha20-Poly1305.")
        }
        
        // Read all ciphertext first (needed for authentication and decryption)
        let allCiphertext = try EncryptionHelpers.readAllData(from: inputStream, bufferSize: bufferSize)
        let ciphertextBytes = Array(allCiphertext)
        
        // XChaCha20: Use HChaCha20 to derive subkey from 24-byte nonce
        var subkey = try hChaCha20(key: Array(fileKeyData), nonce: nonceBytes)
        var poly1305Key: [UInt8] = []
        
        defer {
            // Securely zero out temporary key material
            subkey.secureZero()
            poly1305Key.secureZero()
        }
        
        // Use last 8 bytes of 24-byte nonce, padded with 4 zero bytes to make 12-byte IV
        let xchachaNonceStartIndex = 16
        let xchachaNonceEndIndex = 24
        let xchachaNoncePadding = 4
        let chachaNonce = Array(nonceBytes[xchachaNonceStartIndex..<xchachaNonceEndIndex]) + [UInt8](repeating: 0, count: xchachaNoncePadding)
        
        // Generate Poly1305 key using helper function
        poly1305Key = try EncryptionHelpers.generatePoly1305Key(key: subkey, nonce: chachaNonce)
        
        // Verify authentication tag with Poly1305
        try EncryptionHelpers.verifyPoly1305Tag(
            ciphertext: ciphertextBytes,
            expectedTag: tagBytes,
            poly1305Key: poly1305Key
        )
        
        // Decrypt the ciphertext
        let chacha = try ChaCha20(key: subkey, iv: chachaNonce)
        let plaintext = try chacha.decrypt(ciphertextBytes)
        _ = try outputStream.write(data: Data(plaintext))
    }
}

