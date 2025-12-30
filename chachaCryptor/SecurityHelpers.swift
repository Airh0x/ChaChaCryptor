//
//  SecurityHelpers.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import Foundation

struct SecurityHelpers {
    /// Constant-time comparison of two byte arrays
    /// This prevents timing attacks that could leak information about the authentication tag
    nonisolated static func constantTimeCompare(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        
        let lhsBytes = lhs.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> [UInt8] in
            return Array(bytes)
        }
        let rhsBytes = rhs.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> [UInt8] in
            return Array(bytes)
        }
        
        var result: UInt8 = 0
        for i in 0..<lhs.count {
            result |= lhsBytes[i] ^ rhsBytes[i]
        }
        return result == 0
    }
    
    /// Validates that a key has the expected length (256 bits = 32 bytes)
    nonisolated static func validateKeyLength(_ key: Data, expectedLength: Int = 32) -> Bool {
        return key.count == expectedLength
    }
    
    /// Validates nonce length for the given algorithm
    nonisolated static func validateNonceLength(_ nonce: [UInt8], expectedLength: Int) -> Bool {
        return nonce.count == expectedLength
    }
}

