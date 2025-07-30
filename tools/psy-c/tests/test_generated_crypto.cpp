/**
 * @file test_generated_crypto.cpp
 * @brief Test that psy-c generated code properly uses encryption
 */

#include "generated/basic.hpp"
#include <psyfer.hpp>
#include <iostream>
#include <iomanip>

void test_aes256_encryption() {
    std::cout << "\n=== Testing AES-256 Encryption (psy-c generated) ===\n";
    
    // Create test data
    test::SecureData data;
    data.data = {std::byte{0x48}, std::byte{0x65}, std::byte{0x6c}, std::byte{0x6c}, 
                 std::byte{0x6f}, std::byte{0x20}, std::byte{0x57}, std::byte{0x6f},
                 std::byte{0x72}, std::byte{0x6c}, std::byte{0x64}}; // "Hello World"
    
    // Generate key
    std::array<std::byte, 32> key;
    psyfer::utils::secure_random::generate(key);
    
    // Encrypt
    std::vector<std::byte> encrypted(data.encrypted_size());
    size_t encrypted_size = data.encrypt(encrypted, key);
    
    if (encrypted_size == 0) {
        std::cout << "[FAIL] Encryption failed\n";
        return;
    }
    
    std::cout << "[PASS] Encryption succeeded\n";
    std::cout << "  Original size: " << data.data.size() << " bytes\n";
    std::cout << "  Encrypted size: " << encrypted_size << " bytes\n";
    
    // Decrypt
    auto decrypted = test::SecureData::decrypt(
        std::span<const std::byte>(encrypted.data(), encrypted_size),
        key
    );
    
    if (!decrypted) {
        std::cout << "[FAIL] Decryption failed\n";
        return;
    }
    
    std::cout << "[PASS] Decryption succeeded\n";
    
    // Verify data matches
    bool matches = decrypted->data == data.data;
    std::cout << "[" << (matches ? "PASS" : "FAIL") << "] Data integrity check\n";
}

void test_chacha20_encryption() {
    std::cout << "\n=== Testing ChaCha20 Encryption (psy-c generated) ===\n";
    
    // Create test data
    test::SecureDoc doc;
    doc.content = "This is a secure document with ChaCha20-Poly1305 encryption";
    
    // Generate key
    std::array<std::byte, 32> key;
    psyfer::utils::secure_random::generate(key);
    
    // Encrypt
    std::vector<std::byte> encrypted(doc.encrypted_size());
    size_t encrypted_size = doc.encrypt(encrypted, key);
    
    if (encrypted_size == 0) {
        std::cout << "[FAIL] Encryption failed\n";
        return;
    }
    
    std::cout << "[PASS] Encryption succeeded\n";
    std::cout << "  Original length: " << doc.content.length() << " chars\n";
    std::cout << "  Encrypted size: " << encrypted_size << " bytes\n";
    
    // Decrypt
    auto decrypted = test::SecureDoc::decrypt(
        std::span<const std::byte>(encrypted.data(), encrypted_size),
        key
    );
    
    if (!decrypted) {
        std::cout << "[FAIL] Decryption failed\n";
        return;
    }
    
    std::cout << "[PASS] Decryption succeeded\n";
    
    // Verify data matches
    bool matches = decrypted->content == doc.content;
    std::cout << "[" << (matches ? "PASS" : "FAIL") << "] Data integrity check\n";
}

void test_tampering_detection() {
    std::cout << "\n=== Testing Tampering Detection ===\n";
    
    // Create and encrypt data
    test::SecureData data;
    data.data = {std::byte{0x42}};
    
    std::array<std::byte, 32> key;
    psyfer::utils::secure_random::generate(key);
    
    std::vector<std::byte> encrypted(data.encrypted_size());
    size_t encrypted_size = data.encrypt(encrypted, key);
    
    // Tamper with encrypted data
    encrypted[20] ^= std::byte{0xFF};
    
    // Try to decrypt
    auto decrypted = test::SecureData::decrypt(
        std::span<const std::byte>(encrypted.data(), encrypted_size),
        key
    );
    
    std::cout << "[" << (!decrypted ? "PASS" : "FAIL") 
              << "] Tampering detected (decryption should fail)\n";
}

int main() {
    std::cout << "=== Testing psy-c Generated Encryption Code ===\n";
    std::cout << "Using OpenSSL-backed AES-256-GCM and ChaCha20-Poly1305\n";
    
    test_aes256_encryption();
    test_chacha20_encryption();
    test_tampering_detection();
    
    std::cout << "\n✅ All psy-c encryption tests completed!\n";
    return 0;
}