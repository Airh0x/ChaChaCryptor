//
//  SecureDataHelpers.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import Foundation
import Darwin

// MARK: - Secure Data Handling Helpers
extension Data {
    /// Securely zeros out the data in memory
    nonisolated mutating func secureZero() {
        self.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
            guard let baseAddress = buffer.baseAddress else { return }
            memset_s(baseAddress, buffer.count, 0, buffer.count)
        }
    }
}

extension Array where Element == UInt8 {
    /// Securely zeros out the array in memory
    nonisolated mutating func secureZero() {
        self.withUnsafeMutableBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            memset_s(baseAddress, buffer.count, 0, buffer.count)
        }
    }
}

