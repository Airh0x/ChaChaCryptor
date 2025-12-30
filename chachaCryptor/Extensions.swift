//
//  Extensions.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import Foundation

extension OutputStream {
    nonisolated func write(data: Data) throws -> Int {
        try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Int in
            guard let baseAddress = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            let bytesWritten = self.write(baseAddress, maxLength: data.count)
            if bytesWritten < 0 { throw CryptoError.streamError("Write failed.") }
            return bytesWritten
        }
    }
}

extension InputStream {
    nonisolated func readBytes(count: Int) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        let bytesRead = self.read(&buffer, maxLength: count)
        if bytesRead < count { throw CryptoError.streamError("Could not read required number of bytes. Expected \(count), got \(bytesRead).") }
        return buffer
    }
}

