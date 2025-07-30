#include "test_psy_generated.hpp"
#include <iostream>

int main() {
    std::cout << "Testing psy-c generated serialization...\n\n";
    
    // Test 1: Basic serialization
    {
        std::cout << "=== Test 1: Basic UserData Serialization ===\n";
        
        test::UserData user;
        user.username = "alice";
        user.password = "secret123";
        user.user_id = 42;
        
        // Serialize
        auto serialized = user.serialize();
        std::cout << "Serialized size: " << serialized.size() << " bytes\n";
        
        // Deserialize
        auto deserialized = test::UserData::deserialize(serialized);
        if (deserialized) {
            std::cout << "Deserialized successfully!\n";
            std::cout << "  Username: " << deserialized->username << "\n";
            std::cout << "  User ID: " << deserialized->user_id << "\n";
            std::cout << "  Match: " << (user.username == deserialized->username ? "✅" : "❌") << "\n";
        } else {
            std::cout << "Deserialization failed!\n";
            return 1;
        }
    }
    
    // Test 2: Encrypted serialization
    {
        std::cout << "\n=== Test 2: Encrypted SecureMessage ===\n";
        
        // Generate key
        auto key_result = psyfer::utils::secure_key_256::generate();
        if (!key_result) {
            std::cerr << "Failed to generate key\n";
            return 1;
        }
        auto key = std::move(key_result.value());
        
        test::SecureMessage msg;
        msg.timestamp = 1234567890;
        msg.sender = "bob";
        msg.content = "This is a secret message that should be compressed and encrypted!";
        msg.signature = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
        
        // Encrypt
        size_t encrypted_size = msg.encrypted_size();
        std::vector<std::byte> encrypted(encrypted_size);
        size_t written = msg.encrypt(encrypted, key.span());
        
        if (written > 0) {
            std::cout << "Encrypted successfully!\n";
            std::cout << "  Original content size: " << msg.content.size() << " bytes\n";
            std::cout << "  Encrypted size: " << written << " bytes\n";
            
            // Decrypt
            auto decrypted = test::SecureMessage::decrypt(
                std::span<const std::byte>(encrypted.data(), written), 
                key.span()
            );
            
            if (decrypted) {
                std::cout << "Decrypted successfully!\n";
                std::cout << "  Timestamp: " << decrypted->timestamp << "\n";
                std::cout << "  Sender: " << decrypted->sender << "\n";
                std::cout << "  Content: " << decrypted->content.substr(0, 30) << "...\n";
                std::cout << "  Match: " << (msg.content == decrypted->content ? "✅" : "❌") << "\n";
            } else {
                std::cout << "Decryption failed!\n";
                return 1;
            }
        } else {
            std::cout << "Encryption failed! Written: " << written << "\n";
            return 1;
        }
    }
    
    std::cout << "\n✅ All tests passed!\n";
    return 0;
}