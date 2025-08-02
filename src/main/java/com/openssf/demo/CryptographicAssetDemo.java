package com.openssf.demo;

import java.security.*;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Cryptographic Asset Demo Application
 * Demonstrates the use of protocols, algorithms, and certificates for:
 * - Data at Rest (File encryption/decryption)
 * - Data in Use (Memory encryption)
 * - Data in Transit (TLS/SSL simulation)
 */
public class CryptographicAssetDemo {

    static {
        // Add Bouncy Castle provider for additional crypto support
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String SAMPLE_DATA = "This is sensitive data that needs cryptographic protection";
    private static final String DATA_FILE = "encrypted_data.enc";
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        CryptographicAssetDemo demo = new CryptographicAssetDemo();
        
        System.out.println("🔐 === INTERACTIVE CRYPTOGRAPHIC ASSET DEMO ===");
        System.out.println("Welcome! This demo will guide you through cryptographic concepts step by step.");
        System.out.println("You'll learn about protocols, algorithms, and certificates used to protect:");
        System.out.println("📁 Data at Rest | 💾 Data in Use | 🌐 Data in Transit\n");
        
        try {
            demo.showMainMenu();
            System.out.println("\n🎉 === Demo Complete! Thank you for learning about cryptography! ===");
            
        } catch (Exception e) {
            System.err.println("❌ Error during demo: " + e.getMessage());
            System.err.println("Please check your Java security configuration and ensure all required dependencies are available.");
        } finally {
            scanner.close();
        }
    }

    /**
     * Interactive main menu for the demo
     */
    public void showMainMenu() throws Exception {
        while (true) {
            System.out.println("\n🔒 CRYPTOGRAPHIC CONCEPTS MENU");
            System.out.println("Choose what you'd like to learn about:");
            System.out.println("1. 📁 Data at Rest Protection (File Encryption)");
            System.out.println("2. 💾 Data in Use Protection (Memory Security)");
            System.out.println("3. 📜 Digital Certificates & PKI");
            System.out.println("4. 🌐 Data in Transit Protection (TLS Simulation)");
            System.out.println("5. 🎓 Run Complete Demo (All Concepts)");
            System.out.println("6. ❓ Learn About Cryptographic Algorithms");
            System.out.println("0. 🚪 Exit");
            System.out.print("\nEnter your choice (0-6): ");
            
            int choice = getIntInput();
            System.out.println();
            
            switch (choice) {
                case 1:
                    demonstrateDataAtRest();
                    break;
                case 2:
                    demonstrateDataInUse();
                    break;
                case 3:
                    demonstrateCertificateOperations();
                    break;
                case 4:
                    demonstrateDataInTransit();
                    break;
                case 5:
                    runCompleteDemo();
                    break;
                case 6:
                    explainCryptographicAlgorithms();
                    break;
                case 0:
                    System.out.println("👋 Goodbye! Stay secure!");
                    return;
                default:
                    System.out.println("❌ Invalid choice. Please enter a number between 0-6.");
            }
            
            waitForUser();
        }
    }

    /**
     * Run all demonstrations in sequence
     */
    public void runCompleteDemo() throws Exception {
        System.out.println("🎓 COMPLETE CRYPTOGRAPHIC DEMO");
        System.out.println("This will demonstrate all four key concepts in sequence.\n");
        
        demonstrateDataAtRest();
        waitForUser();
        
        demonstrateDataInUse();
        waitForUser();
        
        demonstrateCertificateOperations();
        waitForUser();
        
        demonstrateDataInTransit();
    }

    /**
     * Demonstrates Data at Rest protection using symmetric encryption
     */
    public void demonstrateDataAtRest() throws Exception {
        System.out.println("📁 === DATA AT REST PROTECTION ===");
        System.out.println("💡 Concept: Protecting data stored on disk (files, databases)");
        System.out.println("🔑 Algorithm: AES-256-GCM (Advanced Encryption Standard)");
        System.out.println("📋 Use Case: Encrypting sensitive files like medical records, financial data");
        
        System.out.println("\n❓ Why AES-256-GCM?");
        System.out.println("   • AES-256: Strong symmetric encryption with 256-bit keys");
        System.out.println("   • GCM mode: Provides both encryption AND authentication");
        System.out.println("   • Prevents tampering: Any change to encrypted data is detected");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 1: Generating encryption key...");

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        System.out.println("✅ Key generated successfully!");
        System.out.println("   📊 Key algorithm: " + secretKey.getAlgorithm());
        System.out.println("   📏 Key length: " + secretKey.getEncoded().length * 8 + " bits");
        System.out.println("   🔐 Key strength: Military-grade encryption");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 2: Encrypting sensitive data...");
        System.out.println("   📝 Original data: \"" + SAMPLE_DATA + "\"");

        // Encrypt data and save to file
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] iv = cipher.getIV();
        byte[] encryptedData = cipher.doFinal(SAMPLE_DATA.getBytes());
        
        // Save encrypted data to file
        try (FileOutputStream fos = new FileOutputStream(DATA_FILE)) {
            fos.write(iv.length);
            fos.write(iv);
            fos.write(encryptedData);
        }
        
        System.out.println("✅ Data encrypted and saved to file: " + DATA_FILE);
        System.out.println("   🆔 IV (Initialization Vector) length: " + iv.length + " bytes");
        System.out.println("   📦 Encrypted data size: " + encryptedData.length + " bytes");
        System.out.println("   🔒 Data is now protected at rest!");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 3: Reading and decrypting the file...");
        
        // Decrypt data from file
        byte[] fileData = Files.readAllBytes(Paths.get(DATA_FILE));
        int ivLength = fileData[0];
        byte[] readIv = Arrays.copyOfRange(fileData, 1, 1 + ivLength);
        byte[] readEncryptedData = Arrays.copyOfRange(fileData, 1 + ivLength, fileData.length);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, readIv));
        byte[] decryptedData = cipher.doFinal(readEncryptedData);
        
        System.out.println("✅ Data successfully decrypted!");
        System.out.println("   📝 Decrypted data: \"" + new String(decryptedData) + "\"");
        System.out.println("   ✔️ Integrity verified: Data hasn't been tampered with");
        
        System.out.println("\n🎯 KEY TAKEAWAY:");
        System.out.println("   Data at rest is protected even if storage is compromised!");
        System.out.println("   Without the key, the data is mathematically unreadable.");
        System.out.println();
    }

    /**
     * Demonstrates Data in Use protection using memory-based encryption
     */
    public void demonstrateDataInUse() throws Exception {
        System.out.println("💾 === DATA IN USE PROTECTION ===");
        System.out.println("💡 Concept: Protecting data while being processed in memory");
        System.out.println("🔑 Algorithm: ChaCha20-Poly1305 (Stream cipher with authentication)");
        System.out.println("📋 Use Case: Processing sensitive data like credit card numbers, passwords");
        
        System.out.println("\n❓ Why ChaCha20-Poly1305?");
        System.out.println("   • ChaCha20: Fast stream cipher, secure against timing attacks");
        System.out.println("   • Poly1305: Authenticator that prevents data tampering");
        System.out.println("   • Mobile-friendly: Better performance than AES on some devices");
        
        waitForUser();

        System.out.println("\n🔄 STEP 1: Generating stream cipher key...");
        
        // Generate ChaCha20 key
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        System.out.println("✅ ChaCha20 key generated!");
        System.out.println("   📊 Algorithm: " + key.getAlgorithm());
        System.out.println("   📏 Key length: " + key.getEncoded().length * 8 + " bits");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 2: Encrypting data in memory...");
        System.out.println("   📝 Sensitive data: \"" + SAMPLE_DATA + "\"");
        
        // Encrypt sensitive data in memory
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] nonce = cipher.getIV();
        byte[] encryptedMemoryData = cipher.doFinal(SAMPLE_DATA.getBytes());

        System.out.println("✅ Data encrypted in memory!");
        System.out.println("   🎲 Nonce length: " + nonce.length + " bytes");
        System.out.println("   📦 Encrypted size: " + encryptedMemoryData.length + " bytes");
        System.out.println("   🛡️ Data is now protected while in use!");

        waitForUser();
        
        System.out.println("\n🔄 STEP 3: Simulating secure processing...");
        System.out.println("   ⚙️ Processing encrypted data (no plaintext in memory)...");
        
        // Process encrypted data (simulation)
        Thread.sleep(1000); // Simulate processing time
        System.out.println("   ✅ Processing complete!");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 4: Decrypting for final use...");
        
        // Decrypt when needed for processing
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] decryptedMemoryData = cipher.doFinal(encryptedMemoryData);
        
        System.out.println("✅ Data decrypted for final processing!");
        System.out.println("   📝 Recovered data: \"" + new String(decryptedMemoryData) + "\"");
        
        // Clear sensitive data from memory
        Arrays.fill(decryptedMemoryData, (byte) 0);
        System.out.println("✅ Sensitive data securely cleared from memory!");
        
        System.out.println("\n🎯 KEY TAKEAWAY:");
        System.out.println("   Even if memory is dumped, sensitive data remains encrypted!");
        System.out.println("   This protects against memory-based attacks and debugging.");
        System.out.println();
    }

    /**
     * Demonstrates certificate operations and PKI
     */
    public void demonstrateCertificateOperations() throws Exception {
        System.out.println("📜 === DIGITAL CERTIFICATES & PKI ===");
        System.out.println("💡 Concept: Establishing trust and identity in digital communications");
        System.out.println("🔑 Algorithm: RSA-2048 with SHA-256");
        System.out.println("📋 Use Case: Website certificates, code signing, email security");
        
        System.out.println("\n❓ What are Digital Certificates?");
        System.out.println("   • Digital ID cards that prove identity");
        System.out.println("   • Contain public key + identity information");
        System.out.println("   • Signed by trusted Certificate Authority (CA)");
        System.out.println("   • Enable secure communication with strangers");
        
        waitForUser();

        System.out.println("\n🔄 STEP 1: Generating RSA key pair...");
        System.out.println("   🎯 Creating public and private keys...");
        
        // Generate RSA key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        System.out.println("✅ RSA key pair generated!");
        System.out.println("   🔓 Public key: Can be shared with everyone");
        System.out.println("   🔐 Private key: Must be kept secret");
        System.out.println("   📏 Key size: 2048 bits (industry standard)");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 2: Creating self-signed certificate...");
        System.out.println("   📝 Adding identity information...");

        // Create self-signed certificate
        X509Certificate certificate = createSelfSignedCertificate(keyPair);
        
        System.out.println("✅ X.509 certificate created!");
        System.out.println("   👤 Subject: " + certificate.getSubjectX500Principal());
        System.out.println("   🏢 Issuer: " + certificate.getIssuerX500Principal());
        System.out.println("   🆔 Serial Number: " + certificate.getSerialNumber());
        System.out.println("   📅 Valid From: " + certificate.getNotBefore());
        System.out.println("   📅 Valid To: " + certificate.getNotAfter());
        System.out.println("   🔑 Public Key Algorithm: " + certificate.getPublicKey().getAlgorithm());
        
        waitForUser();

        System.out.println("\n🔄 STEP 3: Creating digital signature...");
        System.out.println("   📝 Signing data: \"" + SAMPLE_DATA + "\"");
        
        // Digital signature demonstration
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(SAMPLE_DATA.getBytes());
        byte[] digitalSignature = signature.sign();

        System.out.println("✅ Digital signature created!");
        System.out.println("   🔏 Signature algorithm: " + signature.getAlgorithm());
        System.out.println("   📦 Signature length: " + digitalSignature.length + " bytes");
        System.out.println("   🎯 Purpose: Proves data came from private key owner");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 4: Verifying digital signature...");

        // Verify signature
        signature.initVerify(keyPair.getPublic());
        signature.update(SAMPLE_DATA.getBytes());
        boolean verified = signature.verify(digitalSignature);
        
        System.out.println("✅ Signature verification: " + (verified ? "✔️ VALID" : "❌ INVALID"));
        System.out.println("   🔍 Verification proves:");
        System.out.println("     • Data hasn't been changed");
        System.out.println("     • Signature was created by private key owner");
        System.out.println("     • Non-repudiation: Signer can't deny signing");
        
        System.out.println("\n🎯 KEY TAKEAWAY:");
        System.out.println("   Certificates enable trust between parties who've never met!");
        System.out.println("   This is how HTTPS, email security, and code signing work.");
        System.out.println();
    }

    /**
     * Demonstrates Data in Transit protection using TLS concepts
     */
    public void demonstrateDataInTransit() throws Exception {
        System.out.println("🌐 === DATA IN TRANSIT PROTECTION ===");
        System.out.println("💡 Concept: Securing data flowing between systems over networks");
        System.out.println("🔑 Protocol: TLS 1.3 simulation");
        System.out.println("📋 Use Case: HTTPS websites, secure messaging, API communications");
        
        System.out.println("\n❓ What is TLS (Transport Layer Security)?");
        System.out.println("   • Successor to SSL, secures internet communications");
        System.out.println("   • Establishes encrypted tunnel between client and server");
        System.out.println("   • Provides confidentiality, integrity, and authentication");
        System.out.println("   • Used by HTTPS, email, messaging, and more");
        
        waitForUser();

        // Simulate TLS handshake with key exchange
        System.out.println("\n🔄 STEP 1: TLS Handshake - Key Exchange");
        System.out.println("   🤝 Client and server agreeing on encryption keys...");
        
        // 1. Key Exchange using ECDH
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(256);
        
        KeyPair clientKeyPair = ecKeyGen.generateKeyPair();
        KeyPair serverKeyPair = ecKeyGen.generateKeyPair();
        
        System.out.println("✅ Elliptic Curve key pairs generated!");
        System.out.println("   👨‍💻 Client generated ephemeral key pair");
        System.out.println("   🖥️ Server generated ephemeral key pair");
        System.out.println("   🔐 Algorithm: ECDH-256 (Elliptic Curve Diffie-Hellman)");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 2: Shared Secret Computation");
        System.out.println("   🧮 Both parties computing the same secret...");
        
        // 2. Perform key agreement
        KeyAgreement clientKA = KeyAgreement.getInstance("ECDH");
        clientKA.init(clientKeyPair.getPrivate());
        clientKA.doPhase(serverKeyPair.getPublic(), true);
        byte[] clientSharedSecret = clientKA.generateSecret();
        
        KeyAgreement serverKA = KeyAgreement.getInstance("ECDH");
        serverKA.init(serverKeyPair.getPrivate());
        serverKA.doPhase(clientKeyPair.getPublic(), true);
        byte[] serverSharedSecret = serverKA.generateSecret();
        
        boolean secretsMatch = Arrays.equals(clientSharedSecret, serverSharedSecret);
        System.out.println("✅ Shared secret established: " + (secretsMatch ? "✔️ SUCCESS" : "❌ FAILED"));
        System.out.println("   🎯 Magic: Same secret computed without transmitting it!");
        System.out.println("   🛡️ Perfect Forward Secrecy: New secret for each session");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 3: Session Key Derivation");
        System.out.println("   🔑 Converting shared secret into encryption keys...");
        
        // 3. Derive session keys
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sessionKey = sha256.digest(clientSharedSecret);
        SecretKeySpec aesKey = new SecretKeySpec(sessionKey, "AES");
        
        System.out.println("✅ Session key derived!");
        System.out.println("   🔨 Key Derivation Function: SHA-256");
        System.out.println("   🔐 Symmetric encryption key: AES-256");
        System.out.println("   ⚡ Fast symmetric crypto for bulk data transfer");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 4: Secure Data Transmission");
        System.out.println("   📤 Encrypting data for transmission...");
        System.out.println("   📝 Sending: \"" + SAMPLE_DATA + "\"");
        
        // 4. Encrypt data for transmission
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        
        byte[] encryptedTransmission = aesCipher.doFinal(SAMPLE_DATA.getBytes());
        byte[] transmissionIV = aesCipher.getIV();
        
        System.out.println("✅ Data encrypted for transmission!");
        System.out.println("   🔒 Encryption: AES-256-GCM");
        System.out.println("   📦 Transmitted data size: " + encryptedTransmission.length + " bytes");
        System.out.println("   🛡️ Protected against eavesdropping and tampering");
        
        waitForUser();
        
        System.out.println("\n🔄 STEP 5: Secure Data Reception");
        System.out.println("   📥 Receiving and decrypting data...");
        
        // 5. Decrypt received data
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, transmissionIV));
        byte[] decryptedTransmission = aesCipher.doFinal(encryptedTransmission);
        
        System.out.println("✅ Data successfully decrypted!");
        System.out.println("   📝 Received: \"" + new String(decryptedTransmission) + "\"");
        System.out.println("   ✔️ Integrity verified: Data arrived unchanged");
        
        // 6. Display protocol summary
        System.out.println("\n📋 TLS PROTOCOL SUMMARY:");
        System.out.println("   🔑 Key Exchange: ECDH (Elliptic Curve Diffie-Hellman)");
        System.out.println("   🔐 Cipher Suite: AES-256-GCM");
        System.out.println("   🔨 Hash Function: SHA-256");
        System.out.println("   🛡️ Security Level: 128-bit equivalent");
        System.out.println("   ⚡ Performance: Optimized for speed and security");
        
        System.out.println("\n🎯 KEY TAKEAWAY:");
        System.out.println("   TLS creates a secure tunnel over insecure networks!");
        System.out.println("   This is how your browser securely connects to websites.");
        System.out.println("   Even if traffic is intercepted, it's mathematically unreadable.");
    }

    /**
     * Creates a self-signed X.509 certificate using modern Bouncy Castle API
     */
    private X509Certificate createSelfSignedCertificate(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=Demo Certificate, O=OpenSSF Demo, C=US");
        
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject,
            serialNumber,
            notBefore,
            notAfter,
            subject,
            keyPair.getPublic()
        );
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());
        
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certBuilder.build(signer));
    }

    /**
     * Helper method to wait for user input
     */
    private void waitForUser() {
        System.out.print("\n⏸️  Press Enter to continue...");
        scanner.nextLine();
    }

    /**
     * Helper method to get integer input from user
     */
    private int getIntInput() {
        try {
            return Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException e) {
            return -1; // Invalid input
        }
    }

    /**
     * Explains cryptographic algorithms in simple terms
     */
    private void explainCryptographicAlgorithms() {
        System.out.println("🎓 === CRYPTOGRAPHIC ALGORITHMS EXPLAINED ===");
        System.out.println("Let's understand the building blocks of modern cryptography!\n");
        
        System.out.println("🔐 SYMMETRIC ENCRYPTION (Same key for encrypt/decrypt):");
        System.out.println("   📌 AES (Advanced Encryption Standard)");
        System.out.println("      • Most widely used symmetric cipher");
        System.out.println("      • Key sizes: 128, 192, 256 bits");
        System.out.println("      • Used for: File encryption, database encryption");
        System.out.println();
        System.out.println("   📌 ChaCha20");
        System.out.println("      • Modern stream cipher by Google");
        System.out.println("      • Faster than AES on mobile devices");
        System.out.println("      • Used for: Real-time communication, mobile apps");
        System.out.println();
        
        System.out.println("🗝️ ASYMMETRIC ENCRYPTION (Public/Private key pairs):");
        System.out.println("   📌 RSA (Rivest-Shamir-Adleman)");
        System.out.println("      • First practical public key system");
        System.out.println("      • Key sizes: 2048, 3072, 4096 bits");
        System.out.println("      • Used for: Digital signatures, key exchange");
        System.out.println();
        System.out.println("   📌 Elliptic Curve (ECDH, ECDSA)");
        System.out.println("      • Smaller keys, same security as RSA");
        System.out.println("      • More efficient computation");
        System.out.println("      • Used for: Mobile crypto, IoT devices");
        System.out.println();
        
        System.out.println("🔨 HASH FUNCTIONS (One-way mathematical functions):");
        System.out.println("   📌 SHA-256 (Secure Hash Algorithm)");
        System.out.println("      • Produces 256-bit fingerprint");
        System.out.println("      • Used for: Integrity checking, digital signatures");
        System.out.println();
        
        System.out.println("🛡️ AUTHENTICATED ENCRYPTION (Encryption + Integrity):");
        System.out.println("   📌 GCM (Galois/Counter Mode)");
        System.out.println("      • Combines encryption with authentication");
        System.out.println("      • Detects tampering automatically");
        System.out.println();
        System.out.println("   📌 Poly1305");
        System.out.println("      • Authenticator for ChaCha20");
        System.out.println("      • Very fast on modern processors");
        
        System.out.println("\n💡 CHOOSING THE RIGHT ALGORITHM:");
        System.out.println("   • Speed needed? → ChaCha20-Poly1305");
        System.out.println("   • Standard compliance? → AES-GCM");
        System.out.println("   • Digital signatures? → RSA or ECDSA");
        System.out.println("   • Key exchange? → ECDH");
        System.out.println("   • Data integrity? → SHA-256");
    }
}
