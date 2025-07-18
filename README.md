# ChaChaCryptor
File encryptor for iOS

Security Overview
This application employs a robust, multi-layered security architecture to protect user files, leveraging hardware-level protection provided by the Apple Secure Enclave.

The core principle is key wrapping. For each file, a unique symmetric key is randomly generated to encrypt the file's content. This file key is then asymmetrically encrypted ("wrapped") by a master key whose private component is securely stored within and managed by the device's hardware.

Key Security Features
Hardware-Bound Master Key: The master asymmetric key (ECC P-256) is generated and permanently stored within the Secure Enclave. The private key is designed to never leave the device's processor, providing strong protection against OS-level malware and physical extraction attacks.

Asymmetric Key Wrapping (ECIES): For each file, a strong, random 256-bit symmetric key is generated. This "file key" is then encrypted using the master public key via the eciesEncryptionCofactorX963SHA256AESGCM algorithm. This ensures that only the Secure Enclave on the original device can decrypt the file key.

Authenticated Symmetric Encryption: The file content itself is encrypted using AES-256-GCM, which provides both confidentiality and data integrity, protecting against unauthorized access and tampering.

Required User Authentication: Any operation that requires the private master key (such as decrypting a file key) automatically triggers a system-level authentication prompt for the user's Face ID, Touch ID, or device passcode.

Ephemeral Memory Protection: The application processes files in streams to minimize the amount of plaintext data held in RAM. Furthermore, sensitive data, such as decrypted keys and data buffers, is manually zeroed-out from memory immediately after use.

Secure Key Lifecycle: Users have the ability to securely delete and regenerate the master key from within the app, providing a path to invalidate all previously encrypted data if a compromise is suspected.

This design ensures that file confidentiality is tied directly to the physical device hardware, providing a professional-grade security posture for sensitive data.
