/**
 * @file basic_encryption.cpp
 * @brief Example of basic AES-256-GCM encryption using Psyfer
 */

#include <psyfer.hpp>
#include <iostream>
#include <string>
#include <vector>

int main() {
    try {
        // Create a message to encrypt
        std::string message = "Hello, Psyfer! This is a secret message.";
        std::vector<std::byte> plaintext;
        plaintext.reserve(message.size());
        for (char c : message) {
            plaintext.push_back(static_cast<std::byte>(c));
        }
        
        std::cout << "Original message: " << message << std::endl;
        
        // Generate a random key
        psyfer::SecureKey key(psyfer::SecureKey::KeyType::AES_256);
        std::cout << "Generated 256-bit key" << std::endl;
        
        // Create an encryptor
        psyfer::Encryptor encryptor(key);
        
        // Encrypt the message
        std::vector<std::byte> ciphertext;
        auto iv = encryptor.encrypt(plaintext, ciphertext);
        if (iv.empty()) {
            std::cerr << "Encryption failed!" << std::endl;
            return 1;
        }
        
        std::cout << "Encrypted " << plaintext.size() << " bytes -> " 
                  << ciphertext.size() << " bytes (includes IV and tag)" << std::endl;
        
        // Decrypt the message
        std::vector<std::byte> decrypted;
        bool success = encryptor.decrypt(ciphertext, decrypted);
        if (!success) {
            std::cerr << "Decryption failed!" << std::endl;
            return 1;
        }
        
        // Convert back to string and verify
        std::string decrypted_message(
            reinterpret_cast<const char*>(decrypted.data()), 
            decrypted.size()
        );
        
        std::cout << "Decrypted message: " << decrypted_message << std::endl;
        
        if (message == decrypted_message) {
            std::cout << "✓ Success! Encryption and decryption worked correctly." << std::endl;
        } else {
            std::cout << "✗ Error! Decrypted message doesn't match original." << std::endl;
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}