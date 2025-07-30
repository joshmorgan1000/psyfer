/**
 * @file 01_basic_encryption.cpp
 * @brief Basic encryption and decryption examples
 * 
 * This example demonstrates:
 * - Simple encryption/decryption with AES-256-GCM
 * - Simple encryption/decryption with ChaCha20-Poly1305
 * - Key generation
 * - Nonce generation and management
 * - Error handling
 */

#include <psyfer.hpp>
#include <iostream>
#include <string>
#include <vector>

using namespace psyfer;

/**
 * @brief Example 1: Basic AES-256-GCM encryption
 */
void example_aes256_gcm() {
    std::cout << "\n=== Example 1: AES-256-GCM Encryption ===\n";
    
    // Step 1: Generate a secure random key
    // In production, you might derive this from a password or load from secure storage
    auto key_result = utils::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key: " << key_result.error().message() << "\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    // Step 2: Generate a unique nonce (number used once)
    // CRITICAL: Never reuse a nonce with the same key!
    std::array<std::byte, 12> nonce;  // 96-bit nonce for GCM
    auto nonce_err = utils::secure_random::generate(nonce);
    if (nonce_err) {
        std::cerr << "Failed to generate nonce: " << nonce_err.message() << "\n";
        return;
    }
    
    // Step 3: Prepare data to encrypt
    std::string plaintext = "Hello, Psyfer! This is a secret message.";
    std::vector<std::byte> data(
        reinterpret_cast<const std::byte*>(plaintext.data()),
        reinterpret_cast<const std::byte*>(plaintext.data() + plaintext.size())
    );
    
    std::cout << "Original: " << plaintext << "\n";
    std::cout << "Size: " << data.size() << " bytes\n";
    
    // Step 4: Create cipher instance and encrypt in-place
    crypto::aes256_gcm cipher;
    std::array<std::byte, 16> tag;  // 128-bit authentication tag
    
    auto encrypt_err = cipher.encrypt(data, key.span(), nonce, tag);
    if (encrypt_err) {
        std::cerr << "Encryption failed: " << encrypt_err.message() << "\n";
        return;
    }
    
    std::cout << "Encrypted successfully!\n";
    std::cout << "First 16 bytes of ciphertext: ";
    for (size_t i = 0; i < 16 && i < data.size(); ++i) {
        std::cout << std::hex << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << "\n";
    
    // Step 5: Decrypt the data (in-place)
    auto decrypt_err = cipher.decrypt(data, key.span(), nonce, tag);
    if (decrypt_err) {
        std::cerr << "Decryption failed: " << decrypt_err.message() << "\n";
        return;
    }
    
    // Convert back to string
    std::string decrypted(reinterpret_cast<char*>(data.data()), data.size());
    std::cout << "Decrypted: " << decrypted << "\n";
    std::cout << "Success: " << (decrypted == plaintext ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 2: Using ChaCha20-Poly1305
 */
void example_chacha20_poly1305() {
    std::cout << "\n=== Example 2: ChaCha20-Poly1305 Encryption ===\n";
    
    // ChaCha20 is often preferred for:
    // - Software implementations (no hardware requirements)
    // - Mobile/embedded devices
    // - Consistent performance across platforms
    
    // Generate key and nonce
    auto key_result = utils::secure_key_256::generate();
    if (!key_result) return;
    auto key = std::move(key_result.value());
    
    std::array<std::byte, 12> nonce;
    utils::secure_random::generate(nonce);
    
    // Prepare data
    std::string message = "ChaCha20-Poly1305 is a modern AEAD cipher!";
    std::vector<std::byte> data(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    
    // Encrypt
    crypto::chacha20_poly1305 cipher;
    std::array<std::byte, 16> tag;
    
    auto err = cipher.encrypt(data, key.span(), nonce, tag);
    if (err) {
        std::cerr << "Encryption failed: " << err.message() << "\n";
        return;
    }
    
    std::cout << "Encrypted " << message.size() << " bytes with ChaCha20-Poly1305\n";
    
    // Decrypt
    err = cipher.decrypt(data, key.span(), nonce, tag);
    if (err) {
        std::cerr << "Decryption failed: " << err.message() << "\n";
        return;
    }
    
    std::string decrypted(reinterpret_cast<char*>(data.data()), data.size());
    std::cout << "Decrypted: " << decrypted << "\n";
}

/**
 * @brief Example 3: Encryption with Additional Authenticated Data (AAD)
 */
void example_aead_with_aad() {
    std::cout << "\n=== Example 3: AEAD with Additional Authenticated Data ===\n";
    
    // AAD is data that is authenticated but not encrypted
    // Common uses: headers, metadata, routing information
    
    // Setup
    auto key_result = utils::secure_key_256::generate();
    if (!key_result) return;
    auto key = std::move(key_result.value());
    
    std::array<std::byte, 12> nonce;
    utils::secure_random::generate(nonce);
    
    // Message and metadata
    std::string secret_message = "Transfer $1000 to account 12345";
    std::string metadata = "TransactionID: 789, Timestamp: 2024-01-01";
    
    std::vector<std::byte> message_bytes(
        reinterpret_cast<const std::byte*>(secret_message.data()),
        reinterpret_cast<const std::byte*>(secret_message.data() + secret_message.size())
    );
    std::vector<std::byte> aad_bytes(
        reinterpret_cast<const std::byte*>(metadata.data()),
        reinterpret_cast<const std::byte*>(metadata.data() + metadata.size())
    );
    
    std::cout << "Message (will be encrypted): " << secret_message << "\n";
    std::cout << "Metadata (authenticated only): " << metadata << "\n";
    
    // Encrypt with AAD
    crypto::aes256_gcm cipher;
    std::array<std::byte, 16> tag;
    
    auto err = cipher.encrypt(message_bytes, key.span(), nonce, tag, aad_bytes);
    if (err) {
        std::cerr << "Encryption failed: " << err.message() << "\n";
        return;
    }
    
    std::cout << "\nEncrypted message with authenticated metadata\n";
    
    // Decrypt with AAD - must provide the same AAD!
    err = cipher.decrypt(message_bytes, key.span(), nonce, tag, aad_bytes);
    if (err) {
        std::cerr << "Decryption failed: " << err.message() << "\n";
        return;
    }
    
    std::string decrypted(reinterpret_cast<char*>(message_bytes.data()), message_bytes.size());
    std::cout << "Decrypted successfully: " << decrypted << "\n";
    
    // Demonstrate authentication failure with wrong AAD
    std::cout << "\nTrying decryption with modified metadata...\n";
    aad_bytes[0] = std::byte{'X'};  // Tamper with AAD
    
    // Re-encrypt first
    message_bytes.assign(
        reinterpret_cast<const std::byte*>(secret_message.data()),
        reinterpret_cast<const std::byte*>(secret_message.data() + secret_message.size())
    );
    cipher.encrypt(message_bytes, key.span(), nonce, tag, 
                  std::vector<std::byte>(reinterpret_cast<const std::byte*>(metadata.data()), reinterpret_cast<const std::byte*>(metadata.data() + metadata.size())));
    
    // Try to decrypt with wrong AAD
    err = cipher.decrypt(message_bytes, key.span(), nonce, tag, aad_bytes);
    if (err) {
        std::cout << "✅ Authentication correctly failed with tampered AAD\n";
    } else {
        std::cout << "❌ Authentication should have failed!\n";
    }
}

/**
 * @brief Example 4: Handling different data types
 */
void example_different_data_types() {
    std::cout << "\n=== Example 4: Encrypting Different Data Types ===\n";
    
    auto key_result = utils::secure_key_256::generate();
    if (!key_result) return;
    auto key = std::move(key_result.value());
    
    crypto::aes256_gcm cipher;
    
    // Example 4a: Binary data
    {
        std::cout << "\n4a. Binary data:\n";
        std::vector<uint8_t> binary_data = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
        std::vector<std::byte> data(
            reinterpret_cast<std::byte*>(binary_data.data()),
            reinterpret_cast<std::byte*>(binary_data.data() + binary_data.size())
        );
        
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        utils::secure_random::generate(nonce);
        
        cipher.encrypt(data, key.span(), nonce, tag);
        std::cout << "Encrypted " << data.size() << " bytes of binary data\n";
        
        cipher.decrypt(data, key.span(), nonce, tag);
        std::cout << "Decrypted successfully\n";
    }
    
    // Example 4b: Structured data
    {
        std::cout << "\n4b. Structured data:\n";
        struct Record {
            uint32_t id;
            float value;
            uint64_t timestamp;
        } record = {42, 3.14159f, 1234567890};
        
        std::vector<std::byte> data(sizeof(Record));
        std::memcpy(data.data(), &record, sizeof(Record));
        
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        utils::secure_random::generate(nonce);
        
        cipher.encrypt(data, key.span(), nonce, tag);
        std::cout << "Encrypted struct (" << sizeof(Record) << " bytes)\n";
        
        cipher.decrypt(data, key.span(), nonce, tag);
        Record decrypted_record;
        std::memcpy(&decrypted_record, data.data(), sizeof(Record));
        
        std::cout << "Decrypted struct: id=" << decrypted_record.id 
                  << ", value=" << decrypted_record.value 
                  << ", timestamp=" << decrypted_record.timestamp << "\n";
    }
}

int main() {
    std::cout << "Psyfer Basic Encryption Examples\n";
    std::cout << "================================\n";
    
    try {
        example_aes256_gcm();
        example_chacha20_poly1305();
        example_aead_with_aad();
        example_different_data_types();
        
        std::cout << "\n✅ All examples completed successfully!\n";
        
        std::cout << "\nKey Takeaways:\n";
        std::cout << "1. Always use unique nonces - never reuse with the same key\n";
        std::cout << "2. AEAD modes (GCM, Poly1305) provide both encryption and authentication\n";
        std::cout << "3. AAD allows authenticating metadata without encrypting it\n";
        std::cout << "4. Both AES-256-GCM and ChaCha20-Poly1305 are excellent choices\n";
        std::cout << "5. Always handle errors - crypto operations can fail\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}