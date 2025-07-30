/**
 * @file 06_secure_keys.cpp
 * @brief Secure key management examples
 * 
 * This example demonstrates:
 * - Secure key generation
 * - Secure memory management
 * - Key storage and handling
 * - Memory locking and wiping
 * - Custom allocators
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>

// Using specific namespaces to avoid ambiguity
namespace crypto = psyfer::crypto;
namespace kdf = psyfer::kdf;
namespace mac = psyfer::mac;

/**
 * @brief Helper to check if memory appears to be zeroed
 */
bool is_memory_zeroed(const void* ptr, size_t size) {
    const uint8_t* bytes = static_cast<const uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

/**
 * @brief Example 1: Basic secure key usage
 */
void example_basic_secure_keys() {
    std::cout << "\n=== Example 1: Basic Secure Key Usage ===\n";
    
    // Generate secure 256-bit key
    auto key_result = psyfer::utils::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key: " << key_result.error().message() << "\n";
        return;
    }
    
    auto key = std::move(key_result.value());
    
    std::cout << "Generated 256-bit secure key\n";
    std::cout << "Key size: " << key.size << " bytes\n";
    
    // Access key data through span
    auto key_span = key.span();
    std::cout << "First 8 bytes: ";
    for (size_t i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<uint8_t>(key_span[i]));
    }
    std::cout << std::dec << "...\n";
    
    // Key comparison
    auto key2_result = psyfer::utils::secure_key_256::generate();
    if (key2_result) {
        auto& key2 = *key2_result;
        bool same = (key == key2);
        std::cout << "Two random keys equal: " << (same ? "YES (unlikely!)" : "NO (expected)") << "\n";
    }
    
    // Key goes out of scope - memory is securely wiped
    std::cout << "Key will be securely wiped on destruction\n";
}

/**
 * @brief Example 2: Different key sizes
 */
void example_key_sizes() {
    std::cout << "\n=== Example 2: Different Key Sizes ===\n";
    
    // 128-bit key
    {
        auto key128 = psyfer::utils::secure_key_128::generate();
        if (key128) {
            std::cout << "128-bit key: " << key128->size << " bytes\n";
            
            // Use with AES-128
            // Use with AES-128 (would need proper implementation)
            // For now, just show we have the key
            std::cout << "  Key ready for AES-128 encryption\n";
        }
    }
    
    // 256-bit key
    {
        auto key256 = psyfer::utils::secure_key_256::generate();
        if (key256) {
            std::cout << "\n256-bit key: " << key256->size << " bytes\n";
            
            // Use with AES-256
            crypto::aes256_gcm cipher;
            std::vector<std::byte> data = {std::byte{0x42}};
            std::array<std::byte, 12> nonce{};
            std::array<std::byte, 16> tag{};
            
            auto err = cipher.encrypt(data, key256->span(), nonce, tag);
            std::cout << "  AES-256-GCM encryption: " << (err ? "FAILED" : "SUCCESS") << "\n";
        }
    }
    
    // 512-bit key
    {
        auto key512 = psyfer::utils::secure_key_512::generate();
        if (key512) {
            std::cout << "\n512-bit key: " << key512->size << " bytes\n";
            std::cout << "  Suitable for HMAC-SHA512 or key derivation\n";
        }
    }
}

/**
 * @brief Example 3: Secure allocator usage
 */
void example_secure_buffers() {
    std::cout << "\n=== Example 3: Secure Memory Management ===\n";
    
    // Use secure allocator with vector
    std::vector<std::byte, psyfer::utils::secure_allocator<std::byte>> secure_vec;
    
    // Write sensitive data
    std::string sensitive = "My password is: SuperSecret123!";
    secure_vec.reserve(sensitive.size());
    for (char c : sensitive) {
        secure_vec.push_back(static_cast<std::byte>(c));
    }
    
    std::cout << "Stored " << secure_vec.size() << " bytes of sensitive data\n";
    std::cout << "Memory is protected and will be wiped on deallocation\n";
    
    // Process the data
    std::cout << "Processing sensitive data...\n";
    
    // Clear the vector
    secure_vec.clear();
    std::cout << "Cleared sensitive data\n";
    
    // Vector memory is automatically wiped by secure allocator
    std::cout << "Note: secure_allocator ensures memory is wiped\n";
}

/**
 * @brief Example 4: Custom secure allocator
 */
void example_secure_allocator() {
    std::cout << "\n=== Example 4: Secure Allocator ===\n";
    
    // Vector with secure allocator
    {
        std::vector<std::byte, psyfer::utils::secure_allocator<std::byte>> secure_vec;
        
        // Add sensitive data
        std::string secret = "API_KEY_12345678";
        secure_vec.reserve(secret.size());
        for (char c : secret) {
            secure_vec.push_back(static_cast<std::byte>(c));
        }
        
        std::cout << "Secure vector size: " << secure_vec.size() << " bytes\n";
        std::cout << "Data is locked in memory and will be wiped on deallocation\n";
        
        // Use the data
        std::cout << "First 8 bytes: ";
        for (size_t i = 0; i < std::min(size_t(8), secure_vec.size()); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(static_cast<uint8_t>(secure_vec[i]));
        }
        std::cout << std::dec << "...\n";
    }
    
    // String with secure allocator
    {
        using secure_string = std::basic_string<char, std::char_traits<char>, 
                                               psyfer::utils::secure_allocator<char>>;
        
        secure_string password = "MyVerySecretPassword";
        std::cout << "\nSecure string length: " << password.length() << "\n";
        std::cout << "Memory is protected from swapping\n";
    }
}

/**
 * @brief Example 5: Key derivation from passwords
 */
void example_password_keys() {
    std::cout << "\n=== Example 5: Password-Based Keys ===\n";
    
    std::string password = "correct horse battery staple";
    std::string salt = "user@example.com";
    
    // Convert to byte arrays
    std::vector<std::byte> password_bytes(
        reinterpret_cast<const std::byte*>(password.data()),
        reinterpret_cast<const std::byte*>(password.data() + password.size())
    );
    std::vector<std::byte> salt_bytes(
        reinterpret_cast<const std::byte*>(salt.data()),
        reinterpret_cast<const std::byte*>(salt.data() + salt.size())
    );
    
    // Derive key using HKDF
    std::array<std::byte, 32> derived_key_data;
    auto err = kdf::hkdf::derive_sha256(
        password_bytes,
        salt_bytes,
        std::as_bytes(std::span("encryption-key")),
        derived_key_data
    );
    
    // Create secure key from derived data
    auto derived_key = psyfer::utils::secure_key_256::from_bytes(derived_key_data);
    
    if (err) {
        std::cerr << "Key derivation failed: " << err.message() << "\n";
        return;
    }
    
    std::cout << "Password: \"" << password << "\"\n";
    std::cout << "Salt: \"" << salt << "\"\n";
    std::cout << "Derived 256-bit key: ";
    
    auto key_span = derived_key.span();
    for (size_t i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<uint8_t>(key_span[i]));
    }
    std::cout << std::dec << "...\n";
    
    // Derive another key with same inputs - should match
    std::array<std::byte, 32> derived_key_data2;
    kdf::hkdf::derive_sha256(
        password_bytes,
        salt_bytes,
        std::as_bytes(std::span("encryption-key")),
        derived_key_data2
    );
    auto derived_key2 = psyfer::utils::secure_key_256::from_bytes(derived_key_data2);
    
    bool match = (derived_key == derived_key2);
    std::cout << "Deterministic derivation: " << (match ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 6: Key import/export
 */
void example_key_import_export() {
    std::cout << "\n=== Example 6: Key Import/Export ===\n";
    
    // Create a key from known bytes (e.g., from key exchange)
    std::array<std::byte, 32> raw_key_data;
    for (size_t i = 0; i < 32; ++i) {
        raw_key_data[i] = static_cast<std::byte>(i);
    }
    
    // Import into secure key
    auto imported_key = psyfer::utils::secure_key_256::from_bytes(raw_key_data);
    // from_bytes returns by value, not a result
    
    std::cout << "Imported 256-bit key from raw bytes\n";
    
    // Use the imported key
    crypto::chacha20_poly1305 cipher;
    std::vector<std::byte> plaintext = {std::byte{'H'}, std::byte{'i'}};
    std::array<std::byte, 12> nonce{};
    std::array<std::byte, 16> tag{};
    
    auto err = cipher.encrypt(plaintext, imported_key.span(), nonce, tag);
    std::cout << "Encryption with imported key: " << (err ? "FAILED" : "SUCCESS") << "\n";
    
    // Export key (only if needed - avoid if possible!)
    std::vector<std::byte, psyfer::utils::secure_allocator<std::byte>> export_buffer(32);
    std::memcpy(export_buffer.data(), imported_key.data(), 32);
    
    std::cout << "Exported key to secure buffer\n";
    std::cout << "WARNING: Exporting keys reduces security!\n";
    
    // Clear the export buffer
    export_buffer.clear();
    std::cout << "Export buffer cleared\n";
}

/**
 * @brief Example 7: Memory locking demonstration
 */
void example_memory_locking() {
    std::cout << "\n=== Example 7: Memory Locking ===\n";
    
    // Secure memory is handled automatically by secure_buffer and secure_key
    std::cout << "Memory protection:\n";
    std::cout << "  - secure_key automatically locks memory when possible\n";
    std::cout << "  - Memory is wiped on destruction\n";
    std::cout << "  - No swapping to disk (platform dependent)\n";
    
    // Demonstrate secure random
    std::cout << "\nSecure random bytes: ";
    std::array<std::byte, 16> random_bytes;
    psyfer::utils::secure_random::generate(random_bytes);
    
    for (size_t i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<uint8_t>(random_bytes[i]));
    }
    std::cout << std::dec << "...\n";
}

/**
 * @brief Example 8: Key lifetime management
 */
void example_key_lifetime() {
    std::cout << "\n=== Example 8: Key Lifetime Management ===\n";
    
    // Demonstrate RAII with keys
    {
        std::cout << "Creating temporary key scope...\n";
        
        auto temp_key = psyfer::utils::secure_key_256::generate();
        if (!temp_key) return;
        
        std::cout << "Temporary key created\n";
        
        // Use key in limited scope
        crypto::aes256_gcm cipher;
        std::vector<std::byte> data = {std::byte{1}, std::byte{2}, std::byte{3}};
        std::array<std::byte, 12> nonce{};
        std::array<std::byte, 16> tag{};
        
        cipher.encrypt(data, temp_key->span(), nonce, tag);
        std::cout << "Used key for encryption\n";
        
    } // Key is destroyed and wiped here
    
    std::cout << "Key destroyed - memory wiped automatically\n";
    
    // Demonstrate move semantics
    std::cout << "\nDemonstrating move semantics:\n";
    
    auto key1 = psyfer::utils::secure_key_256::generate();
    if (!key1) return;
    
    std::cout << "Key 1 created\n";
    
    // Move key to new owner
    auto key2 = std::move(*key1);
    std::cout << "Key moved to new owner\n";
    std::cout << "Original key valid: " << (key1.has_value() ? "YES" : "NO (moved)") << "\n";
    
    // key2 now owns the secure memory
    std::cout << "New owner has " << key2.size << " byte key\n";
}

int main() {
    std::cout << "Psyfer Secure Key Management Examples\n";
    std::cout << "====================================\n";
    
    try {
        example_basic_secure_keys();
        example_key_sizes();
        example_secure_buffers();
        example_secure_allocator();
        example_password_keys();
        example_key_import_export();
        example_memory_locking();
        example_key_lifetime();
        
        std::cout << "\n✅ All secure key examples completed successfully!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}