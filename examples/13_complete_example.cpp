/**
 * @file 13_complete_example.cpp
 * @brief Comprehensive example using PsyferContext
 * 
 * This example demonstrates:
 * - Creating and configuring a PsyferContext
 * - All encryption methods (symmetric, asymmetric)
 * - Digital signatures
 * - HMAC authentication
 * - Key derivation
 * - Context persistence (save/load)
 * - Integration with psy-c objects
 */

#include <psyfer.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

using namespace psyfer;

/**
 * @brief Helper to print data as hex
 */
void print_hex(const std::string& label, std::span<const std::byte> data, size_t max_bytes = 32) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(static_cast<uint8_t>(data[i]));
    }
    if (data.size() > max_bytes) std::cout << "...";
    std::cout << std::dec << " (" << data.size() << " bytes)\n";
}

/**
 * @brief Example 1: Basic PsyferContext usage
 */
void example_basic_context() {
    std::cout << "\n=== Example 1: Basic PsyferContext Usage ===\n";
    
    // Create a context with custom configuration
    PsyferContext::Config config;
    config.identity_name = "Alice's Laptop";
    config.key_rotation_period = std::chrono::hours(24 * 7);  // Weekly rotation
    
    auto ctx_result = PsyferContext::create(config);
    if (!ctx_result) {
        std::cerr << "Failed to create context: " << ctx_result.error().message() << "\n";
        return;
    }
    
    auto& ctx = *ctx_result.value();
    
    std::cout << "Created context for: " << ctx.identity() << "\n";
    print_hex("Public key (X25519)", ctx.get_public_key());
    print_hex("Signing key (Ed25519)", ctx.get_signing_public_key());
    
    // Simple string encryption
    std::string secret = "This is my secret message!";
    auto encrypted = ctx.encrypt_string(secret);
    if (!encrypted) {
        std::cerr << "Encryption failed: " << encrypted.error().message() << "\n";
        return;
    }
    
    std::cout << "\nOriginal: " << secret << "\n";
    print_hex("Encrypted", *encrypted);
    
    // Decrypt
    auto decrypted = ctx.decrypt_string(*encrypted);
    if (!decrypted) {
        std::cerr << "Decryption failed: " << decrypted.error().message() << "\n";
        return;
    }
    
    std::cout << "Decrypted: " << *decrypted << "\n";
    std::cout << "Match: " << (*decrypted == secret ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 2: Symmetric encryption with different algorithms
 */
void example_symmetric_crypto() {
    std::cout << "\n=== Example 2: Symmetric Encryption Options ===\n";
    
    auto ctx_result = PsyferContext::create();
    if (!ctx_result) return;
    auto& ctx = *ctx_result.value();
    
    // Test data
    std::string plaintext = "Testing different encryption algorithms";
    std::vector<std::byte> data(
        reinterpret_cast<const std::byte*>(plaintext.data()),
        reinterpret_cast<const std::byte*>(plaintext.data() + plaintext.size())
    );
    
    // AES-256-GCM
    {
        std::cout << "\nAES-256-GCM:\n";
        std::vector<std::byte> aes_data = data;
        
        auto result = ctx.encrypt_aes(aes_data);
        if (!result) {
            std::cerr << "AES encryption failed\n";
            return;
        }
        
        print_hex("Nonce", result->nonce);
        print_hex("Tag", result->tag);
        print_hex("Ciphertext", aes_data);
        
        // Decrypt
        auto err = ctx.decrypt_aes(aes_data, result->nonce, result->tag);
        if (err) {
            std::cerr << "AES decryption failed: " << err.message() << "\n";
            return;
        }
        
        std::string decrypted(reinterpret_cast<char*>(aes_data.data()), aes_data.size());
        std::cout << "Decrypted: " << decrypted << "\n";
    }
    
    // ChaCha20-Poly1305
    {
        std::cout << "\nChaCha20-Poly1305:\n";
        std::vector<std::byte> chacha_data = data;
        
        auto result = ctx.encrypt_chacha(chacha_data);
        if (!result) {
            std::cerr << "ChaCha20 encryption failed\n";
            return;
        }
        
        print_hex("Nonce", result->nonce);
        print_hex("Tag", result->tag);
        print_hex("Ciphertext", chacha_data);
        
        // Decrypt
        auto err = ctx.decrypt_chacha(chacha_data, result->nonce, result->tag);
        if (err) {
            std::cerr << "ChaCha20 decryption failed: " << err.message() << "\n";
            return;
        }
        
        std::string decrypted(reinterpret_cast<char*>(chacha_data.data()), chacha_data.size());
        std::cout << "Decrypted: " << decrypted << "\n";
    }
}

/**
 * @brief Example 3: Asymmetric encryption between contexts
 */
void example_asymmetric_crypto() {
    std::cout << "\n=== Example 3: Asymmetric Encryption (X25519) ===\n";
    
    // Create two contexts (Alice and Bob)
    PsyferContext::Config alice_config;
    alice_config.identity_name = "Alice";
    auto alice_result = PsyferContext::create(alice_config);
    if (!alice_result) return;
    auto& alice = *alice_result.value();
    
    PsyferContext::Config bob_config;
    bob_config.identity_name = "Bob";
    auto bob_result = PsyferContext::create(bob_config);
    if (!bob_result) return;
    auto& bob = *bob_result.value();
    
    std::cout << "Created contexts for Alice and Bob\n";
    print_hex("Alice's public key", alice.get_public_key());
    print_hex("Bob's public key", bob.get_public_key());
    
    // Alice encrypts for Bob
    std::string message = "Hey Bob, this is a secret message from Alice!";
    std::vector<std::byte> plaintext(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    
    auto encrypted = alice.encrypt_for(plaintext, bob.get_public_key());
    if (!encrypted) {
        std::cerr << "Encryption failed: " << encrypted.error().message() << "\n";
        return;
    }
    
    std::cout << "\nAlice encrypts for Bob:\n";
    std::cout << "Message: " << message << "\n";
    print_hex("Encrypted", *encrypted);
    
    // Bob decrypts from Alice
    auto decrypted = bob.decrypt_from(*encrypted, alice.get_public_key());
    if (!decrypted) {
        std::cerr << "Decryption failed: " << decrypted.error().message() << "\n";
        return;
    }
    
    std::string recovered(
        reinterpret_cast<char*>(decrypted->data()),
        decrypted->size()
    );
    std::cout << "\nBob decrypts from Alice:\n";
    std::cout << "Recovered: " << recovered << "\n";
    std::cout << "Match: " << (recovered == message ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 4: Digital signatures
 */
void example_signatures() {
    std::cout << "\n=== Example 4: Digital Signatures (Ed25519) ===\n";
    
    auto ctx_result = PsyferContext::create();
    if (!ctx_result) return;
    auto& ctx = *ctx_result.value();
    
    // Sign a message
    std::string document = "I, Alice, agree to the terms and conditions.";
    auto signature = ctx.sign_string(document);
    if (!signature) {
        std::cerr << "Signing failed: " << signature.error().message() << "\n";
        return;
    }
    
    std::cout << "Document: " << document << "\n";
    print_hex("Signature", *signature);
    print_hex("Public key", ctx.get_signing_public_key());
    
    // Verify signature
    bool valid = ctx.verify(
        std::as_bytes(std::span(document)),
        *signature,
        ctx.get_signing_public_key()
    );
    
    std::cout << "Signature verification: " << (valid ? "✅ VALID" : "❌ INVALID") << "\n";
    
    // Try with tampered document
    std::string tampered = "I, Alice, agree to give all my money.";
    bool tampered_valid = ctx.verify(
        std::as_bytes(std::span(tampered)),
        *signature,
        ctx.get_signing_public_key()
    );
    
    std::cout << "Tampered document verification: " 
              << (tampered_valid ? "❌ VALID (bad!)" : "✅ INVALID (good!)") << "\n";
}

/**
 * @brief Example 5: HMAC authentication
 */
void example_hmac() {
    std::cout << "\n=== Example 5: HMAC Authentication ===\n";
    
    auto ctx_result = PsyferContext::create();
    if (!ctx_result) return;
    auto& ctx = *ctx_result.value();
    
    // Create authenticated message
    std::string message = "Transfer $1000 to account 12345";
    auto mac = ctx.hmac256(std::as_bytes(std::span(message)));
    
    std::cout << "Message: " << message << "\n";
    print_hex("HMAC-SHA256", mac);
    
    // Verify MAC
    bool valid = ctx.verify_hmac256(std::as_bytes(std::span(message)), mac);
    std::cout << "Verification: " << (valid ? "✅ VALID" : "❌ INVALID") << "\n";
    
    // Larger MAC with SHA512
    auto mac512 = ctx.hmac512(std::as_bytes(std::span(message)));
    print_hex("HMAC-SHA512", mac512);
}

/**
 * @brief Example 6: Key derivation
 */
void example_key_derivation() {
    std::cout << "\n=== Example 6: Key Derivation ===\n";
    
    auto ctx_result = PsyferContext::create();
    if (!ctx_result) return;
    auto& ctx = *ctx_result.value();
    
    // Derive keys for different purposes
    auto storage_key = ctx.derive_key("storage-encryption");
    if (!storage_key) {
        std::cerr << "Failed to derive storage key\n";
        return;
    }
    
    auto api_key = ctx.derive_key("api-authentication");
    if (!api_key) {
        std::cerr << "Failed to derive API key\n";
        return;
    }
    
    std::cout << "Derived specialized keys:\n";
    print_hex("Storage key", storage_key->span());
    print_hex("API key", api_key->span());
    
    // Derive with custom salt
    std::string salt_str = "user@example.com";
    std::vector<std::byte> salt(
        reinterpret_cast<const std::byte*>(salt_str.data()),
        reinterpret_cast<const std::byte*>(salt_str.data() + salt_str.size())
    );
    
    auto user_key = ctx.derive_key("user-specific", salt);
    if (!user_key) {
        std::cerr << "Failed to derive user key\n";
        return;
    }
    
    std::cout << "\nUser-specific key (salt: " << salt_str << "):\n";
    print_hex("User key", user_key->span());
}

/**
 * @brief Example 7: Context persistence
 */
void example_persistence() {
    std::cout << "\n=== Example 7: Context Persistence ===\n";
    
    // Generate a master key for context encryption
    auto master_key_result = psyfer::secure_key_256::generate();
    if (!master_key_result) {
        std::cerr << "Failed to generate master key\n";
        return;
    }
    auto master_key = std::move(master_key_result.value());
    
    std::string test_message = "Persistence test";
    std::vector<std::byte> encrypted_data;
    
    // Create and save context
    {
        PsyferContext::Config config;
        config.identity_name = "Persistent Identity";
        
        auto ctx_result = PsyferContext::create(config);
        if (!ctx_result) return;
        auto& ctx = *ctx_result.value();
        
        // Encrypt something to test later
        auto encrypted = ctx.encrypt_string(test_message);
        if (!encrypted) return;
        encrypted_data = std::move(*encrypted);
        
        // Save context
        auto saved = ctx.save(master_key.span());
        if (!saved) {
            std::cerr << "Failed to save context: " << saved.error().message() << "\n";
            return;
        }
        
        std::cout << "Saved context (" << saved->size() << " bytes)\n";
        
        // Write to file (in real app, store securely)
        std::ofstream file("context.psy", std::ios::binary);
        file.write(reinterpret_cast<const char*>(saved->data()), saved->size());
        file.close();
    }
    
    // Load context
    {
        // Read from file
        std::ifstream file("context.psy", std::ios::binary);
        std::string file_content((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
        std::vector<std::byte> saved_data(
            reinterpret_cast<const std::byte*>(file_content.data()),
            reinterpret_cast<const std::byte*>(file_content.data() + file_content.size())
        );
        file.close();
        
        auto ctx_result = PsyferContext::load(saved_data, master_key.span());
        if (!ctx_result) {
            std::cerr << "Failed to load context: " << ctx_result.error().message() << "\n";
            return;
        }
        auto& ctx = *ctx_result.value();
        
        std::cout << "Loaded context for: " << ctx.identity() << "\n";
        
        // Decrypt the previously encrypted data
        auto decrypted = ctx.decrypt_string(encrypted_data);
        if (!decrypted) {
            std::cerr << "Failed to decrypt: " << decrypted.error().message() << "\n";
            return;
        }
        
        std::cout << "Decrypted message: " << *decrypted << "\n";
        std::cout << "Persistence test: " << (*decrypted == test_message ? "✅ PASSED" : "❌ FAILED") << "\n";
        
        // Clean up
        std::remove("context.psy");
    }
}

/**
 * @brief Example 8: Integration with psy-c objects
 */
void example_psy_integration() {
    std::cout << "\n=== Example 8: psy-c Integration ===\n";
    
    // Simulated psy-c object (from example 12)
    struct UserData {
        std::string username;
        uint32_t user_id;
        
        size_t encrypted_size() const {
            return username.size() + sizeof(user_id) + 32; // Extra space for metadata
        }
        
        size_t encrypt(std::span<std::byte> buffer, std::span<const std::byte, 32> key) const {
            if (buffer.size() < encrypted_size()) return 0;
            
            // Simple example: just XOR with key (NOT SECURE - for demo only)
            size_t pos = 0;
            
            // Write username length and data
            uint32_t name_len = username.size();
            std::memcpy(buffer.data() + pos, &name_len, sizeof(name_len));
            pos += sizeof(name_len);
            
            std::memcpy(buffer.data() + pos, username.data(), username.size());
            pos += username.size();
            
            // Write user_id
            std::memcpy(buffer.data() + pos, &user_id, sizeof(user_id));
            pos += sizeof(user_id);
            
            // "Encrypt" by XORing with key bytes (demo only)
            for (size_t i = 0; i < pos; ++i) {
                buffer[i] ^= key[i % 32];
            }
            
            return pos;
        }
        
        // Static decrypt for PsyferContext compatibility
        static size_t decrypt(std::span<const std::byte> source_buffer,
                             UserData* target,
                             std::span<const std::byte, 32> key) {
            return target->decrypt(source_buffer, key);
        }
        
        size_t decrypt(std::span<const std::byte> buffer, std::span<const std::byte, 32> key) {
            if (buffer.size() < sizeof(uint32_t)) return 0;
            
            // Make a copy to decrypt
            std::vector<std::byte> decrypted(
        reinterpret_cast<const std::byte*>(buffer.data()),
        reinterpret_cast<const std::byte*>(buffer.data() + buffer.size())
    );
            
            // "Decrypt" by XORing with key bytes
            for (size_t i = 0; i < decrypted.size(); ++i) {
                decrypted[i] ^= key[i % 32];
            }
            
            size_t pos = 0;
            
            // Read username length
            uint32_t name_len;
            std::memcpy(&name_len, decrypted.data() + pos, sizeof(name_len));
            pos += sizeof(name_len);
            
            if (pos + name_len + sizeof(user_id) > decrypted.size()) return 0;
            
            // Read username
            username.assign(
                reinterpret_cast<char*>(decrypted.data() + pos),
                name_len
            );
            pos += name_len;
            
            // Read user_id
            std::memcpy(&user_id, decrypted.data() + pos, sizeof(user_id));
            pos += sizeof(user_id);
            
            return pos;
        }
    };
    
    auto ctx_result = PsyferContext::create();
    if (!ctx_result) return;
    auto& ctx = *ctx_result.value();
    
    // Create and encrypt object
    UserData user;
    user.username = "alice@example.com";
    user.user_id = 12345;
    
    // Encrypt using the object's method
    size_t enc_size = user.encrypted_size();
    std::vector<std::byte> encrypted(enc_size);
    size_t written = user.encrypt(encrypted, ctx.get_psy_key());
    if (written == 0) {
        std::cerr << "Failed to encrypt object\n";
        return;
    }
    encrypted.resize(written);
    
    std::cout << "Original: " << user.username << " (ID: " << user.user_id << ")\n";
    print_hex("Encrypted object", encrypted);
    print_hex("psy-c key", ctx.get_psy_key());
    
    // Decrypt object
    UserData decrypted;
    size_t consumed = decrypted.decrypt(encrypted, ctx.get_psy_key());
    if (consumed == 0) {
        std::cerr << "Failed to decrypt object\n";
        return;
    }
    
    std::cout << "Decrypted: " << decrypted.username << " (ID: " << decrypted.user_id << ")\n";
    std::cout << "Match: " << (decrypted.username == user.username && 
                              decrypted.user_id == user.user_id ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 9: Key rotation
 */
void example_key_rotation() {
    std::cout << "\n=== Example 9: Key Rotation ===\n";
    
    // Create context with short rotation period for demo
    PsyferContext::Config config;
    config.identity_name = "Rotation Demo";
    config.key_rotation_period = std::chrono::hours(0);  // Immediate rotation needed
    
    auto ctx_result = PsyferContext::create(config);
    if (!ctx_result) return;
    auto& ctx = *ctx_result.value();
    
    // Get initial keys
    auto initial_pubkey = ctx.get_public_key();
    auto initial_signing_key = ctx.get_signing_public_key();
    
    std::cout << "Initial keys:\n";
    print_hex("X25519 public", initial_pubkey);
    print_hex("Ed25519 public", initial_signing_key);
    
    // Check rotation need
    std::cout << "\nNeeds rotation: " << (ctx.needs_rotation() ? "YES" : "NO") << "\n";
    
    // Rotate keys
    auto err = ctx.rotate_keys();
    if (err) {
        std::cerr << "Key rotation failed: " << err.message() << "\n";
        return;
    }
    
    std::cout << "\nAfter rotation:\n";
    print_hex("X25519 public", ctx.get_public_key());
    print_hex("Ed25519 public", ctx.get_signing_public_key());
    
    // Note: In production, you'd need to:
    // 1. Notify peers about new public keys
    // 2. Keep old keys for decrypting old data
    // 3. Re-encrypt sensitive data with new keys
}

int main() {
    std::cout << "Psyfer Complete Example with PsyferContext\n";
    std::cout << "==========================================\n";
    
    try {
        example_basic_context();
        example_symmetric_crypto();
        example_asymmetric_crypto();
        example_signatures();
        example_hmac();
        example_key_derivation();
        example_persistence();
        example_psy_integration();
        example_key_rotation();
        
        std::cout << "\n✅ All examples completed successfully!\n";
        
        std::cout << "\nPsyferContext Benefits:\n";
        std::cout << "1. Single object manages all crypto operations\n";
        std::cout << "2. Automatic key management and derivation\n";
        std::cout << "3. Built-in support for all Psyfer algorithms\n";
        std::cout << "4. Easy persistence and key rotation\n";
        std::cout << "5. Seamless integration with psy-c generated code\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}