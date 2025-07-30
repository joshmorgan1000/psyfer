/**
 * @file simple_encrypt_method.cpp
 * @brief Simple example demonstrating the requested encrypt method
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <span>

using namespace psyfer;

/**
 * @brief Example class with the requested encrypt method
 */
class EncryptableObject {
private:
    std::vector<std::byte> data_;
    
public:
    EncryptableObject(const std::string& text) {
        data_.resize(text.size());
        std::memcpy(data_.data(), text.data(), text.size());
    }
    
    /**
     * @brief Encrypt the object's data with the given key
     * @param key Encryption key (must be 32 bytes)
     * @return Encrypted data as a vector, or empty vector on error
     */
    [[nodiscard]] std::vector<std::byte> encrypt(
        std::span<const std::byte> key
    ) const {
        // Validate key size
        if (key.size() != 32) {
            std::cerr << "Error: Key must be exactly 32 bytes\n";
            return {};
        }
        
        // Prepare encryption
        psyfer::aes256_gcm cipher;
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        
        // Generate random nonce
        auto err = secure_random::generate(nonce);
        if (err) {
            std::cerr << "Error generating nonce: " << err.message() << "\n";
            return {};
        }
        
        // Allocate result buffer: nonce + tag + encrypted data
        std::vector<std::byte> result(nonce.size() + tag.size() + data_.size());
        
        // Copy nonce to beginning of result
        std::memcpy(result.data(), nonce.data(), nonce.size());
        
        // Copy data to encrypt into result buffer (after nonce and tag space)
        std::memcpy(result.data() + nonce.size() + tag.size(), data_.data(), data_.size());
        
        // Encrypt in-place
        std::span<std::byte> data_span(result.data() + nonce.size() + tag.size(), data_.size());
        err = cipher.encrypt(
            data_span,
            std::span<const std::byte, 32>(key.data(), 32),
            nonce,
            tag
        );
        
        if (err) {
            std::cerr << "Encryption failed: " << err.message() << "\n";
            return {};
        }
        
        // Copy tag to result
        std::memcpy(result.data() + nonce.size(), tag.data(), tag.size());
        
        return result;
    }
    
    /**
     * @brief Decrypt data that was encrypted with encrypt()
     * @param encrypted_data Data returned by encrypt()
     * @param key Decryption key (same as used for encryption)
     * @return Decrypted data as a vector, or empty vector on error
     */
    [[nodiscard]] static std::vector<std::byte> decrypt(
        std::span<const std::byte> encrypted_data,
        std::span<const std::byte> key
    ) {
        // Validate inputs
        if (key.size() != 32) {
            std::cerr << "Error: Key must be exactly 32 bytes\n";
            return {};
        }
        
        if (encrypted_data.size() < 28) { // nonce(12) + tag(16)
            std::cerr << "Error: Encrypted data too small\n";
            return {};
        }
        
        // Extract components
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        
        std::memcpy(nonce.data(), encrypted_data.data(), nonce.size());
        std::memcpy(tag.data(), encrypted_data.data() + nonce.size(), tag.size());
        
        // Prepare decryption
        size_t data_size = encrypted_data.size() - nonce.size() - tag.size();
        std::vector<std::byte> result(data_size);
        
        // Copy encrypted data
        std::memcpy(result.data(), 
                    encrypted_data.data() + nonce.size() + tag.size(), 
                    data_size);
        
        // Decrypt in-place
        psyfer::aes256_gcm cipher;
        auto err = cipher.decrypt(
            result,
            std::span<const std::byte, 32>(key.data(), 32),
            nonce,
            tag
        );
        
        if (err) {
            std::cerr << "Decryption failed: " << err.message() << "\n";
            return {};
        }
        
        return result;
    }
};

int main() {
    std::cout << "Simple Encrypt Method Example\n";
    std::cout << "=============================\n\n";
    
    try {
        // Create an object with some data
        EncryptableObject obj("Hello, this is a secret message!");
        std::cout << "Created object with secret message\n";
        
        // Generate a key
        std::array<std::byte, 32> key;
        auto err = secure_random::generate(key);
        if (err) {
            std::cerr << "Failed to generate key: " << err.message() << "\n";
            return 1;
        }
        std::cout << "Generated 256-bit encryption key\n";
        
        // Encrypt using the method with the exact signature requested
        std::vector<std::byte> encrypted = obj.encrypt(std::span<const std::byte>(key.data(), key.size()));
        
        if (encrypted.empty()) {
            std::cerr << "Encryption failed!\n";
            return 1;
        }
        
        std::cout << "✅ Encrypted successfully\n";
        std::cout << "  Encrypted size: " << encrypted.size() << " bytes\n";
        std::cout << "  (12 byte nonce + 16 byte tag + " 
                  << (encrypted.size() - 28) << " byte ciphertext)\n";
        
        // Decrypt to verify
        std::vector<std::byte> decrypted = EncryptableObject::decrypt(encrypted, std::span<const std::byte>(key.data(), key.size()));
        
        if (decrypted.empty()) {
            std::cerr << "Decryption failed!\n";
            return 1;
        }
        
        std::cout << "✅ Decrypted successfully\n";
        
        // Convert back to string
        std::string decrypted_text(
            reinterpret_cast<const char*>(decrypted.data()),
            decrypted.size()
        );
        
        std::cout << "  Decrypted message: \"" << decrypted_text << "\"\n";
        
        // Test with invalid key size
        std::cout << "\nTesting error handling:\n";
        std::vector<std::byte> short_key(16); // Too short
        std::vector<std::byte> result = obj.encrypt(short_key);
        
        if (result.empty()) {
            std::cout << "✅ Correctly rejected invalid key size\n";
        } else {
            std::cout << "❌ Should have rejected invalid key size\n";
        }
        
        std::cout << "\n✅ All tests passed!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}