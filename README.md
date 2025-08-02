# Cryptographic Asset Demo

A simple Java application demonstrating the practical use of cryptographic protocols, algorithms, and certificates in securing data at rest, in use, and in transit.

## Overview

This demo application showcases three fundamental aspects of cryptography:

1. **Data at Rest** - Protecting stored data using AES-256-GCM encryption
2. **Data in Use** - Securing data during processing using ChaCha20-Poly1305
3. **Data in Transit** - Simulating TLS 1.3 protocol for secure communication

## Cryptographic Assets Demonstrated

### Algorithms
- **AES-256-GCM**: Advanced Encryption Standard with Galois/Counter Mode
- **ChaCha20-Poly1305**: Stream cipher with authenticated encryption
- **RSA-2048**: Public key cryptography for digital signatures
- **ECDH-256**: Elliptic Curve Diffie-Hellman for key exchange
- **SHA-256**: Secure Hash Algorithm for integrity verification

### Protocols
- **TLS 1.3 Simulation**: Transport Layer Security handshake and data encryption
- **PKI Operations**: Public Key Infrastructure with certificate management

### Certificates
- **X.509 Certificates**: Self-signed certificate creation and validation
- **Digital Signatures**: RSA-based signing and verification

## Prerequisites

- Java 11 or higher
- Maven 3.6+

## Building and Running

1. **Clone and navigate to the project directory:**
   ```bash
   cd /home/anataraj/Projects/openssf-demoapp/cryptographic-asset-demo
   ```

2. **Build the project:**
   ```bash
   mvn clean compile
   ```

3. **Run the demo:**
   ```bash
   mvn exec:java
   ```

   Or alternatively:
   ```bash
   mvn clean compile exec:java -Dexec.mainClass="com.openssf.demo.CryptographicAssetDemo"
   ```

## Demo Flow

The application will demonstrate:

1. **Data at Rest Protection**
   - Encrypt sensitive data using AES-256-GCM
   - Save encrypted data to a file
   - Read and decrypt the data from the file

2. **Data in Use Protection**
   - Encrypt data in memory using ChaCha20-Poly1305
   - Process encrypted data securely
   - Clear sensitive data from memory

3. **Certificate Operations**
   - Generate RSA key pairs
   - Create self-signed X.509 certificates
   - Perform digital signing and verification

4. **Data in Transit Protection**
   - Simulate TLS handshake with ECDH key exchange
   - Establish shared secrets
   - Encrypt and decrypt data for transmission

## Security Features

- **Strong Encryption**: Uses industry-standard algorithms (AES-256, ChaCha20)
- **Authenticated Encryption**: Prevents tampering with GCM and Poly1305 modes
- **Perfect Forward Secrecy**: ECDH key exchange ensures session key security
- **Memory Safety**: Explicit clearing of sensitive data from memory
- **Certificate Validation**: Demonstrates PKI certificate operations

## Educational Value

This demo helps understand:
- How different cryptographic algorithms are used in practice
- The role of certificates in establishing trust
- Protocol design for secure communication
- Best practices for handling sensitive data

## Dependencies

- **Bouncy Castle**: Additional cryptographic algorithms and certificate utilities
- **Jackson**: JSON processing (minimal usage)

## Security Notes

This is an educational demo. For production use:
- Use proper key management systems
- Implement certificate authority validation
- Use established TLS libraries instead of custom implementations
- Follow security best practices for key storage and rotation

## Output Example

When you run the demo, you'll see output like:

```
=== Cryptographic Asset Demo ===
Demonstrating cryptographic protocols, algorithms, and certificates

1. DATA AT REST PROTECTION
Algorithm: AES-256-GCM (Advanced Encryption Standard)
Use Case: Encrypting files stored on disk

✓ Data encrypted and saved to: encrypted_data.enc
  Original data: This is sensitive data that needs cryptographic protection
  Key algorithm: AES
  Key length: 256 bits
✓ Data decrypted from file: This is sensitive data that needs cryptographic protection

[... additional output for other demonstrations ...]
```

## Files Created

The demo creates temporary files during execution:
- `encrypted_data.enc` - Contains encrypted data for the "data at rest" demonstration

These files are safe to delete after the demo completes.
