/**
 * @file password_encryption.cpp
 * @brief Example of password-based encryption using Psyfer
 */

#include <psyfer.hpp>
#include <iostream>
#include <string>
#include <vector>

int main() {
    try {
        // Get password from user (in real app, use secure input)
        std::string password = "MySecretPassword123!";
        std::string message = "This message is encrypted with a password-derived key.";
        
        std::cout << "Password: " << password << std::endl;
        std::cout << "Message: " << message << std::endl;
        
        // Generate a random salt (store this with the encrypted data)
        psyfer::SecureKey salt(psyfer::SecureKey::KeyType::AES_256);
        std::cout << "\nGenerated salt: " << salt.to_hex() << std::endl;
        
        // Derive key from password
        psyfer::SecureKey key = psyfer::SecureKey::from_password(
            password, 
            {salt.data(), salt.size()}
        );
        std::cout << "Derived key from password" << std::endl;
        
        // Create encryptor with derived key
        psyfer::AES256GCMEncryptor encryptor(key);
        
        // Encrypt
        std::vector<std::byte> plaintext;
        plaintext.reserve(message.size());
        for (char c : message) {
            plaintext.push_back(static_cast<std::byte>(c));
        }
        std::vector<std::byte> ciphertext(encryptor.ciphertext_size(plaintext.size()));
        
        if (!encryptor.encrypt(plaintext, ciphertext)) {
            std::cerr << "Encryption failed!" << std::endl;
            return 1;
        }
        
        std::cout << "\nEncrypted message (" << ciphertext.size() << " bytes)" << std::endl;
        
        // Simulate decryption with the same password
        std::cout << "\nDecrypting with password..." << std::endl;
        
        // Re-derive the key from password (using same salt)
        psyfer::SecureKey key2 = psyfer::SecureKey::from_password(
            password, 
            {salt.data(), salt.size()}
        );
        
        // Create new encryptor for decryption
        psyfer::AES256GCMEncryptor decryptor(key2);
        
        // Decrypt
        std::vector<std::byte> decrypted(plaintext.size());
        if (!decryptor.decrypt(ciphertext, decrypted)) {
            std::cerr << "Decryption failed!" << std::endl;
            return 1;
        }
        
        std::string decrypted_message(
            reinterpret_cast<const char*>(decrypted.data()), 
            decrypted.size()
        );
        
        std::cout << "Decrypted: " << decrypted_message << std::endl;
        
        // Try with wrong password
        std::cout << "\nTrying with wrong password..." << std::endl;
        psyfer::SecureKey wrong_key = psyfer::SecureKey::from_password(
            "WrongPassword", 
            {salt.data(), salt.size()}
        );
        
        psyfer::AES256GCMEncryptor wrong_decryptor(wrong_key);
        std::vector<std::byte> wrong_decrypted(plaintext.size());
        
        if (!wrong_decryptor.decrypt(ciphertext, wrong_decrypted)) {
            std::cout << "✓ Good! Wrong password correctly rejected." << std::endl;
        } else {
            std::cout << "✗ Error! Wrong password should have failed." << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}