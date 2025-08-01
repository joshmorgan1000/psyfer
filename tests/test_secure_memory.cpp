/**
 * @file test_secure_memory.cpp
 * @brief Tests for secure memory handling
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <cstring>

int main() {
    std::cout << "=== Secure Memory Tests ===" << std::endl;
    
    try {
        // Test 1: SecureKey creation and destruction
        {
            std::cout << "\nTest 1: SecureKey lifecycle" << std::endl;
            
            psyfer::SecureKey* key = new psyfer::SecureKey(32);
            
            if (!key->is_empty()) {
                std::cout << "✓ SecureKey allocated" << std::endl;
            } else {
                std::cerr << "✗ SecureKey allocation failed" << std::endl;
                return 1;
            }
            
            delete key;
            std::cout << "✓ SecureKey destroyed (memory should be cleared)" << std::endl;
        }
        
        // Test 2: Move semantics
        {
            std::cout << "\nTest 2: SecureKey move semantics" << std::endl;
            
            psyfer::SecureKey key1(32);
            auto hex_before = key1.to_hex();
            
            psyfer::SecureKey key2(std::move(key1));
            auto hex_after = key2.to_hex();
            
            if (hex_before == hex_after) {
                std::cout << "✓ Key moved successfully" << std::endl;
            } else {
                std::cerr << "✗ Key move failed" << std::endl;
                return 1;
            }
            
            // key1 should now be empty
            if (key1.is_empty()) {
                std::cout << "✓ Original key properly cleared after move" << std::endl;
            } else {
                std::cerr << "✗ Original key not cleared after move" << std::endl;
                return 1;
            }
        }
        
        // Test 3: Key clearing
        {
            std::cout << "\nTest 3: Explicit key clearing" << std::endl;
            
            psyfer::SecureKey key(32);
            
            // Get key data before clearing
            auto key_data = key.get_key();
            bool all_zero_before = true;
            for (auto byte : key_data) {
                if (byte != 0) {
                    all_zero_before = false;
                    break;
                }
            }
            
            if (!all_zero_before) {
                std::cout << "✓ Key contains non-zero data" << std::endl;
            }
            
            key.clear();
            
            // Verify key is cleared
            key_data = key.get_key();
            bool all_zero_after = true;
            for (auto byte : key_data) {
                if (byte != 0) {
                    all_zero_after = false;
                    break;
                }
            }
            
            if (all_zero_after) {
                std::cout << "✓ Key cleared successfully" << std::endl;
            } else {
                std::cerr << "✗ Key not properly cleared" << std::endl;
                return 1;
            }
        }
        
        // Test 4: Multiple keys don't interfere
        {
            std::cout << "\nTest 4: Key isolation" << std::endl;
            
            psyfer::SecureKey key1 = psyfer::SecureKey::generate(32);
            psyfer::SecureKey key2 = psyfer::SecureKey::generate(32);
            
            if (!(key1 == key2)) {
                std::cout << "✓ Different keys are unique" << std::endl;
            } else {
                std::cerr << "✗ Key generation produced identical keys" << std::endl;
                return 1;
            }
        }
        
        // Test 5: Encryptor with secure keys
        {
            std::cout << "\nTest 5: Encryptor secure key management" << std::endl;
            
            psyfer::Encryptor* enc = new psyfer::Encryptor(true);
            
            std::vector<uint8_t> data = {1, 2, 3, 4, 5};
            std::vector<uint8_t> encrypted(data.size() + 16 + 12); // Room for IV + GCM tag
            
            enc->encrypt(data, encrypted);
            std::cout << "✓ Encryption with secure key successful" << std::endl;
            
            delete enc;
            std::cout << "✓ Encryptor destroyed (keys should be cleared)" << std::endl;
        }
        
        std::cout << "\n✓ All secure memory tests passed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}