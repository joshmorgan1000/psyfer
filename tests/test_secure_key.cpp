/**
 * @file test_secure_key.cpp
 * @brief Tests for SecureKey convenience class
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <thread>

/**
 * @brief Print a byte array as hex
 */
void print_hex(const std::string& label, std::span<const std::byte> data) {
    std::cout << label << ": ";
    for (const auto& byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<unsigned int>(static_cast<uint8_t>(byte));
    }
    std::cout << std::dec << std::endl;
}

/**
 * @brief Test basic key generation and management
 */
void test_key_generation() {
    std::cout << "Testing key generation..." << std::endl;
    
    // Generate AES-256 key
    auto key_result = psyfer::utils::aes256_key::generate();
    assert(key_result.has_value());
    auto& key = key_result.value();
    
    assert(!key.is_empty());
    print_hex("Generated AES-256 key", key.span());
    
    // Generate another key
    auto key2_result = psyfer::utils::aes256_key::generate();
    assert(key2_result.has_value());
    
    // Keys should be different
    assert(!(key == key2_result.value()));
    std::cout << "✓ Multiple keys are unique" << std::endl;
    
    // Test different key sizes
    auto key128 = psyfer::utils::secure_key_128::generate();
    assert(key128.has_value());
    assert(key128.value().span().size() == 16);
    std::cout << "✓ 128-bit key generation works" << std::endl;
    
    auto key512 = psyfer::utils::secure_key_512::generate();
    assert(key512.has_value());
    assert(key512.value().span().size() == 64);
    std::cout << "✓ 512-bit key generation works" << std::endl;
}

/**
 * @brief Test creating keys from existing data
 */
void test_key_from_bytes() {
    std::cout << "\nTesting key from bytes..." << std::endl;
    
    // Create known key data
    std::array<std::byte, 32> key_data;
    for (size_t i = 0; i < 32; ++i) {
        key_data[i] = static_cast<std::byte>(i);
    }
    
    auto key = psyfer::utils::aes256_key::from_bytes(key_data);
    
    // Verify key matches input
    bool matches = true;
    for (size_t i = 0; i < 32; ++i) {
        if (key.span()[i] != key_data[i]) {
            matches = false;
            break;
        }
    }
    assert(matches);
    std::cout << "✓ Key created correctly from bytes" << std::endl;
    
    // Test clearing
    key.clear();
    assert(key.is_empty());
    std::cout << "✓ Key cleared successfully" << std::endl;
}

/**
 * @brief Test password-based key derivation
 */
void test_key_derivation() {
    std::cout << "\nTesting password-based key derivation..." << std::endl;
    
    std::string password = "SuperSecretPassword123!";
    std::array<std::byte, 32> salt;
    for (size_t i = 0; i < 32; ++i) {
        salt[i] = static_cast<std::byte>(i * 7 + 13);
    }
    
    // Derive key with default iterations
    auto key_result = psyfer::utils::aes256_key::from_password(
        password, salt, 10000  // Reduced for testing
    );
    assert(key_result.has_value());
    print_hex("Derived key", key_result.value().span());
    
    // Same password and salt should produce same key
    auto key2_result = psyfer::utils::aes256_key::from_password(
        password, salt, 10000
    );
    assert(key2_result.has_value());
    assert(key_result.value() == key2_result.value());
    std::cout << "✓ Key derivation is deterministic" << std::endl;
    
    // Different password should produce different key
    auto key3_result = psyfer::utils::aes256_key::from_password(
        "DifferentPassword", salt, 10000
    );
    assert(key3_result.has_value());
    assert(!(key_result.value() == key3_result.value()));
    std::cout << "✓ Different passwords produce different keys" << std::endl;
    
    // Different salt should produce different key
    salt[0] = std::byte{0xFF};
    auto key4_result = psyfer::utils::aes256_key::from_password(
        password, salt, 10000
    );
    assert(key4_result.has_value());
    assert(!(key_result.value() == key4_result.value()));
    std::cout << "✓ Different salts produce different keys" << std::endl;
}

/**
 * @brief Test key age and rotation
 */
void test_key_rotation() {
    std::cout << "\nTesting key age and rotation..." << std::endl;
    
    auto key_result = psyfer::utils::aes256_key::generate();
    assert(key_result.has_value());
    auto& key = key_result.value();
    
    // Check initial age
    auto age = key.age();
    assert(age.count() >= 0);
    std::cout << "✓ Key age tracking works" << std::endl;
    
    // Test rotation check
    assert(!key.should_rotate(std::chrono::hours(24)));
    
    // Sleep briefly to test age increase
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto new_age = key.age();
    assert(new_age > age);
    
    // Test with very short rotation period
    assert(key.should_rotate(std::chrono::microseconds(1)));
    std::cout << "✓ Key rotation check works" << std::endl;
}

/**
 * @brief Test key export/import with protection
 */
void test_key_protection() {
    std::cout << "\nTesting key export/import with protection..." << std::endl;
    
    // Generate key to protect
    auto key_result = psyfer::utils::aes256_key::generate();
    assert(key_result.has_value());
    auto& key = key_result.value();
    
    // Generate protection key
    auto protection_key = psyfer::utils::secure_random::generate_key<32>();
    assert(protection_key.has_value());
    
    // Export protected
    auto export_result = key.export_protected(protection_key.value());
    assert(export_result.has_value());
    print_hex("Protected key export", export_result.value());
    
    // Import back
    auto import_result = psyfer::utils::aes256_key::import_protected(
        export_result.value(),
        protection_key.value()
    );
    assert(import_result.has_value());
    
    // Should match original
    assert(key == import_result.value());
    std::cout << "✓ Key export/import successful" << std::endl;
    
    // Try with wrong protection key
    auto wrong_key = psyfer::utils::secure_random::generate_key<32>();
    assert(wrong_key.has_value());
    
    auto bad_import = psyfer::utils::aes256_key::import_protected(
        export_result.value(),
        wrong_key.value()
    );
    assert(!bad_import.has_value());
    std::cout << "✓ Import with wrong key fails as expected" << std::endl;
    
    // Try with corrupted data
    export_result.value()[0] ^= std::byte{0xFF};
    auto corrupt_import = psyfer::utils::aes256_key::import_protected(
        export_result.value(),
        protection_key.value()
    );
    assert(!corrupt_import.has_value());
    std::cout << "✓ Import with corrupted data fails as expected" << std::endl;
}

/**
 * @brief Test integration with crypto operations
 */
void test_crypto_integration() {
    std::cout << "\nTesting integration with crypto operations..." << std::endl;
    
    // Generate key using SecureKey
    auto key_result = psyfer::utils::aes256_key::generate();
    assert(key_result.has_value());
    
    // Generate nonce
    auto nonce = psyfer::utils::secure_random::generate_nonce<12>();
    assert(nonce.has_value());
    
    // Encrypt data
    std::string plaintext = "Test message for SecureKey";
    std::vector<std::byte> data;
    data.reserve(plaintext.size());
    for (char c : plaintext) {
        data.push_back(static_cast<std::byte>(c));
    }
    
    std::array<std::byte, 16> tag;
    auto ec = psyfer::crypto::aes256_gcm::encrypt_oneshot(
        data,
        key_result.value().span(),
        nonce.value(),
        tag,
        {}
    );
    assert(!ec);
    std::cout << "✓ Encryption with SecureKey successful" << std::endl;
    
    // Decrypt
    ec = psyfer::crypto::aes256_gcm::decrypt_oneshot(
        data,
        key_result.value().span(),
        nonce.value(),
        tag,
        {}
    );
    assert(!ec);
    
    std::string decrypted;
    decrypted.reserve(data.size());
    for (std::byte b : data) {
        decrypted.push_back(static_cast<char>(b));
    }
    assert(decrypted == plaintext);
    std::cout << "✓ Decryption with SecureKey successful" << std::endl;
}

/**
 * @brief Test key type aliases
 */
void test_key_aliases() {
    std::cout << "\nTesting key type aliases..." << std::endl;
    
    // Test all predefined key types
    auto aes_key = psyfer::utils::aes256_key::generate();
    assert(aes_key.has_value());
    assert(aes_key.value().span().size() == 32);
    
    auto chacha_key = psyfer::utils::chacha20_key::generate();
    assert(chacha_key.has_value());
    assert(chacha_key.value().span().size() == 32);
    
    auto x25519_key = psyfer::utils::x25519_private_key::generate();
    assert(x25519_key.has_value());
    assert(x25519_key.value().span().size() == 32);
    
    auto blake3_key = psyfer::utils::blake3_key::generate();
    assert(blake3_key.has_value());
    assert(blake3_key.value().span().size() == 32);
    
    std::cout << "✓ All key type aliases work correctly" << std::endl;
}

int main() {
    std::cout << "=== SecureKey Tests ===" << std::endl;
    
    test_key_generation();
    test_key_from_bytes();
    test_key_derivation();
    test_key_rotation();
    test_key_protection();
    test_crypto_integration();
    test_key_aliases();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}