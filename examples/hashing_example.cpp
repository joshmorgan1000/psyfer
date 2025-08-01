/**
 * @file hashing_example.cpp
 * @brief Example of SHA-256 and HMAC-SHA256 hashing using Psyfer
 */

#include <psyfer.hpp>
#include <iostream>
#include <string>
#include <iomanip>

void print_hex(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    try {
        // Example 1: SHA-256 hashing
        std::cout << "=== SHA-256 Hashing ===" << std::endl;
        
        std::string message1 = "Hello, World!";
        std::cout << "Message: " << message1 << std::endl;
        
        auto hash1 = psyfer::sha256(
            reinterpret_cast<const uint8_t*>(message1.data()), 
            message1.size()
        );
        print_hex(hash1, "SHA-256");
        
        // Hash a different message
        std::string message2 = "Hello, World"; // Missing exclamation
        auto hash2 = psyfer::sha256(
            reinterpret_cast<const uint8_t*>(message2.data()), 
            message2.size()
        );
        std::cout << "\nMessage: " << message2 << std::endl;
        print_hex(hash2, "SHA-256");
        
        std::cout << "\nNote: Even a small change produces a completely different hash!" << std::endl;
        
        // Example 2: HMAC-SHA256
        std::cout << "\n=== HMAC-SHA256 ===" << std::endl;
        
        // Create a secret key for HMAC
        psyfer::SecureKey hmac_key(psyfer::SecureKey::KeyType::AES_256);
        std::cout << "HMAC Key: " << hmac_key.to_hex().substr(0, 32) << "..." << std::endl;
        
        std::string data = "Important message to authenticate";
        std::cout << "Data: " << data << std::endl;
        
        auto hmac = psyfer::hmac_sha256(
            hmac_key.data(), hmac_key.size(),
            reinterpret_cast<const uint8_t*>(data.data()), data.size()
        );
        print_hex(hmac, "HMAC-SHA256");
        
        // Verify HMAC with same key
        auto hmac_verify = psyfer::hmac_sha256(
            hmac_key.data(), hmac_key.size(),
            reinterpret_cast<const uint8_t*>(data.data()), data.size()
        );
        
        if (hmac == hmac_verify) {
            std::cout << "✓ HMAC verification successful!" << std::endl;
        } else {
            std::cout << "✗ HMAC verification failed!" << std::endl;
        }
        
        // Try with different key (should produce different HMAC)
        psyfer::SecureKey different_key(psyfer::SecureKey::KeyType::AES_256);
        auto hmac_different = psyfer::hmac_sha256(
            different_key.data(), different_key.size(),
            reinterpret_cast<const uint8_t*>(data.data()), data.size()
        );
        
        if (hmac != hmac_different) {
            std::cout << "✓ Different keys produce different HMACs (as expected)" << std::endl;
        }
        
        // Example 3: File hashing
        std::cout << "\n=== Hashing larger data ===" << std::endl;
        
        // Create some test data
        std::vector<uint8_t> large_data(1024 * 1024, 0xAB); // 1MB of data
        std::cout << "Hashing 1MB of data..." << std::endl;
        
        auto large_hash = psyfer::sha256(large_data.data(), large_data.size());
        print_hex(large_hash, "SHA-256 of 1MB");
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}