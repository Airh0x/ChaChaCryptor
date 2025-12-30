# ChaChaCryptor

A military-grade file encryption application for iOS that provides hardware-bound encryption using Apple's Secure Enclave.

![Build Status](https://github.com/Airh0x/ChaChaCryptor/workflows/Build%20and%20Test/badge.svg)

## Overview

ChaChaCryptor is a secure file encryption tool designed for iOS devices. It employs a robust, multi-layered security architecture to protect user files, leveraging hardware-level protection provided by the Apple Secure Enclave. Files encrypted on one device can only be decrypted on that same device, ensuring maximum security for sensitive data.

## Key Features

- **Hardware-Bound Encryption**: Master key is stored in Secure Enclave and never leaves the device
- **Multiple Encryption Algorithms**: Supports AES-256-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305
- **Stream-Based Processing**: Efficiently handles large files using streaming encryption
- **Biometric Authentication**: Requires Face ID, Touch ID, or device passcode for all operations
- **Device-Specific**: Encrypted files cannot be decrypted on other devices
- **Memory Security**: All sensitive data is securely zeroed from memory after use
- **Timing Attack Protection**: Constant-time comparison for authentication tag verification

## Security Architecture

### Hardware-Bound Master Key

The master asymmetric key (ECC P-256) is generated and permanently stored within the Secure Enclave. The private key is designed to never leave the device's processor, providing strong protection against OS-level malware and physical extraction attacks.

**Key Properties:**
- Algorithm: ECDSA P-256 (256-bit)
- Storage: Secure Enclave (hardware-protected)
- Access Control: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Authentication: `.userPresence` flag requires Face ID/Touch ID/passcode

### Asymmetric Key Wrapping (ECIES)

For each file, a strong, random 256-bit symmetric key is generated. This "file key" is then encrypted using the master public key via the `eciesEncryptionCofactorX963SHA256AESGCM` algorithm. This ensures that only the Secure Enclave on the original device can decrypt the file key.

### Supported Encryption Algorithms

1. **AES-256-GCM**
   - Key length: 256 bits
   - Mode: GCM (Authenticated Encryption)
   - Nonce size: 12 bytes
   - Tag size: 16 bytes
   - Standard: NIST recommended, used in military applications

2. **ChaCha20-Poly1305**
   - Key length: 256 bits
   - Stream cipher + MAC
   - Nonce size: 12 bytes
   - Tag size: 16 bytes
   - Standard: RFC 8439 compliant, used by Google Chrome

3. **XChaCha20-Poly1305**
   - Key length: 256 bits
   - Extended nonce version (24 bytes)
   - Tag size: 16 bytes
   - Standard: Reduces nonce reuse risk

All algorithms provide authenticated encryption (AEAD), ensuring both confidentiality and data integrity.

### File Format

Encrypted files use the following format:
```
[algorithm(1 byte)][keyLength(4 bytes)][encryptedFileKey][nonce(variable)][tag(16 bytes)][ciphertext]
```

- **Algorithm**: Identifies the encryption algorithm used (0=AES-256-GCM, 1=ChaCha20-Poly1305, 2=XChaCha20-Poly1305)
- **Key Length**: Length of the encrypted file key (big-endian UInt32)
- **Encrypted File Key**: ECIES-encrypted 256-bit symmetric key
- **Nonce**: Random nonce (12 bytes for AES/ChaCha20, 24 bytes for XChaCha20)
- **Tag**: Authentication tag (16 bytes)
- **Ciphertext**: Encrypted file content

**Backward Compatibility**: The app supports older file formats (without algorithm identifier) for decryption.

## Security Features

### Ephemeral Memory Protection

The application processes files in streams to minimize the amount of plaintext data held in RAM. Furthermore, sensitive data, such as decrypted keys and data buffers, is manually zeroed-out from memory immediately after use using `secureZero()`.

### Timing Attack Protection

All authentication tag verifications use constant-time comparison (`SecurityHelpers.constantTimeCompare`) to prevent timing attacks.

### Input Validation

Comprehensive input validation prevents:
- Integer overflow attacks
- DoS attacks
- Invalid file format attacks

All key lengths, nonce lengths, and tag lengths are validated before use.

### Secure Key Lifecycle

Users have the ability to securely delete and regenerate the master key from within the app, providing a path to invalidate all previously encrypted data if a compromise is suspected.

## Requirements

- iOS 15.0 or later
- Device with Secure Enclave support (iPhone 5s or later, iPad Air or later)
- Face ID, Touch ID, or device passcode enabled

## Installation

### Prerequisites

1. Add CryptoSwift via Swift Package Manager:
   ```
   https://github.com/CryptoSwift/CryptoSwift
   ```

2. In your project's `Info.plist`, add:
   ```xml
   <key>NSFaceIDUsageDescription</key>
   <string>Authentication is required to access encrypted files.</string>
   ```

### Building

1. Open `chachaCryptor.xcodeproj` in Xcode
2. Select your target device or simulator
3. Build and run (⌘R)

## Usage

1. **Select Encryption Algorithm**: Choose from AES-256-GCM, ChaCha20-Poly1305, or XChaCha20-Poly1305
2. **Encrypt File**: Tap "Encrypt File" and select a file. The encrypted file will be saved with a `.enc` extension.
3. **Decrypt File**: Tap "Decrypt File" and select an encrypted file. The decrypted file will be saved without the `.enc` extension.
4. **Reset Master Key**: Use the "Reset Master Key" button in the Danger Zone to delete the master key (this will make all previously encrypted files unreadable).

## Important Warnings

⚠️ **Device-Specific Encryption**: Files encrypted on this device can only be decrypted on this device. They cannot be recovered if you:
- Switch to a new device
- Perform a factory reset
- Delete the master key
- Restore from a backup that doesn't include Secure Enclave data

⚠️ **Master Key Deletion**: Resetting the master key will permanently make all previously encrypted files unreadable. This action cannot be undone.

## Security Audit

A comprehensive security audit has been conducted. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for detailed security evaluation.

**Security Level**: ⭐⭐⭐⭐⭐ (5/5)

The application meets military-grade encryption requirements and implements best practices for:
- Cryptographic algorithms
- Key management
- Memory security
- Timing attack protection
- Input validation

## Technical Details

### Dependencies

- **CryptoSwift**: For ChaCha20-Poly1305 and XChaCha20-Poly1305 encryption
- **CryptoKit**: For AES-256-GCM encryption and key generation
- **Security Framework**: For Secure Enclave integration
- **LocalAuthentication**: For biometric authentication

### Architecture

- **CryptoManager**: Main coordinator for encryption/decryption operations
- **SecureEnclaveManager**: Manages master key in Secure Enclave
- **EncryptionService**: Handles stream-based encryption/decryption
- **EncryptionHelpers**: Utility functions for encryption operations
- **SecurityHelpers**: Security utilities (constant-time comparison, validation)

### CI/CD

This project uses GitHub Actions for continuous integration and automated builds:

- **Automated Builds**: Builds are automatically triggered on pushes to `main` and `develop` branches, and on pull requests
- **Build Targets**: 
  - iOS Simulator (iPhone 15, latest OS)
  - iOS Device (generic platform)
- **Artifacts**: Build artifacts are automatically archived and available for 7 days

See `.github/workflows/build.yml` for the complete workflow configuration.

**Note**: This application is designed for security-conscious users who need device-specific encryption. Always maintain backups of your master key recovery information if you need to transfer encrypted files between devices (though this is not currently supported by design).
