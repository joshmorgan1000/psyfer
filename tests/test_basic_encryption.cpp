/**
 * @file test_basic_encryption.cpp
 * @brief Basic sanity tests for the simplified Psyfer encryption API
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

int main() {
    std::cout << "=== Basic Encryption Tests ===" << std::endl;
    
    try {
        // Test 1: Basic key generation and encryption/decryption
        {
            std::cout << "\nTest 1: Basic encryption/decryption" << std::endl;
            
            psyfer::Encryptor enc(true); // Generate key automatically
            
            std::string plaintext = "Hello, World! This is a test message.";
            std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
            std::vector<uint8_t> ciphertext(plaintext_bytes.size() + 16 + 12); // Room for IV + GCM tag
            
            enc.encrypt(plaintext_bytes, ciphertext);
            std::cout << "✓ Encryption successful" << std::endl;
            
            std::vector<uint8_t> decrypted(plaintext_bytes.size());
            enc.decrypt(ciphertext, decrypted);
            
            std::string result(decrypted.begin(), decrypted.end());
            if (result == plaintext) {
                std::cout << "✓ Decryption successful" << std::endl;
            } else {
                std::cerr << "✗ Decryption failed - data mismatch" << std::endl;
                return 1;
            }
        }
        
        // Test 2: Using SecureKey
        {
            std::cout << "\nTest 2: SecureKey generation and usage" << std::endl;
            
            psyfer::SecureKey key(32); // 32 bytes for AES-256
            std::cout << "✓ SecureKey created" << std::endl;
            
            psyfer::Encryptor enc(std::move(key));
            
            std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
            std::vector<uint8_t> encrypted(data.size() + 16 + 12);
            
            enc.encrypt(data, encrypted);
            std::cout << "✓ Encryption with SecureKey successful" << std::endl;
        }
        
        // Test 3: Key from hex
        {
            std::cout << "\nTest 3: Key from hex string" << std::endl;
            
            psyfer::SecureKey key1 = psyfer::SecureKey::generate(32);
            std::string hex = key1.to_hex();
            std::cout << "Key hex: " << hex.substr(0, 16) << "..." << std::endl;
            
            psyfer::SecureKey key2 = psyfer::SecureKey::from_hex(hex);
            
            if (key1 == key2) {
                std::cout << "✓ Key hex conversion successful" << std::endl;
            } else {
                std::cerr << "✗ Key hex conversion failed" << std::endl;
                return 1;
            }
        }
        
        // Test 4: SHA-256 hashing
        {
            std::cout << "\nTest 4: SHA-256 hashing" << std::endl;
            
            psyfer::Encryptor enc(true); // Generate key for hashing context
            
            std::string message = "The quick brown fox jumps over the lazy dog";
            std::vector<uint8_t> data(message.begin(), message.end());
            
            auto hash = enc.sha256(data);
            
            // Convert hash to hex for display
            std::string hex_hash;
            for (auto byte : hash) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", byte);
                hex_hash += buf;
            }
            
            std::cout << "SHA-256: " << hex_hash << std::endl;
            
            // Known SHA-256 for this message
            if (hex_hash == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592") {
                std::cout << "✓ SHA-256 hash correct" << std::endl;
            } else {
                std::cerr << "✗ SHA-256 hash incorrect" << std::endl;
                return 1;
            }
        }
        
        // Test 5: HMAC-SHA256
        {
            std::cout << "\nTest 5: HMAC-SHA256" << std::endl;
            
            psyfer::SecureKey key = psyfer::SecureKey::generate(32);
            psyfer::Encryptor enc(std::move(key));
            
            std::string message = "Test message for HMAC";
            std::vector<uint8_t> data(message.begin(), message.end());
            
            auto hmac = enc.hmac_sha256(data);
            
            if (hmac.size() == 32) { // SHA256 produces 32 bytes
                std::cout << "✓ HMAC-SHA256 successful (32 bytes)" << std::endl;
            } else {
                std::cerr << "✗ HMAC-SHA256 failed - wrong size" << std::endl;
                return 1;
            }
        }
        
        // Test 6: Key from password
        {
            std::cout << "\nTest 6: Key derivation from password" << std::endl;
            
            std::string password = "my_secure_password";
            std::vector<uint8_t> salt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            
            psyfer::SecureKey key = psyfer::SecureKey::from_password(password, salt);
            
            // Verify deterministic
            psyfer::SecureKey key2 = psyfer::SecureKey::from_password(password, salt);
            
            if (key == key2) {
                std::cout << "✓ Password key derivation is deterministic" << std::endl;
            } else {
                std::cerr << "✗ Password key derivation not deterministic" << std::endl;
                return 1;
            }
        }
        
        std::cout << "\n✓ All tests passed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}