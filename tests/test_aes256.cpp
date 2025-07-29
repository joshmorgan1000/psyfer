/**
 * @file test_aes256.cpp
 * @brief Tests for AES-256 encryption implementation
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <random>

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
 * @brief Test basic AES-256 block encryption
 */
void test_aes256_block() {
    std::cout << "Testing AES-256 block cipher..." << std::endl;
    
    // Test vector from NIST
    std::array<std::byte, 32> key{};
    std::array<std::byte, 16> plaintext{};
    
    // All zeros key and plaintext
    psyfer::crypto::aes256 cipher(key);
    
    std::array<std::byte, 16> block;
    std::memcpy(block.data(), plaintext.data(), 16);
    
    cipher.encrypt_block(block);
    print_hex("Encrypted block", block);
    
    // Decrypt back
    cipher.decrypt_block(block);
    
    // Should match original plaintext
    assert(std::memcmp(block.data(), plaintext.data(), 16) == 0);
    std::cout << "✓ Block encryption/decryption works correctly" << std::endl;
}

/**
 * @brief Test AES-256-GCM encryption
 */
void test_aes256_gcm_basic() {
    std::cout << "\nTesting AES-256-GCM authenticated encryption..." << std::endl;
    
    // Generate random key and nonce
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);
    
    std::array<std::byte, 32> key;
    for (auto& b : key) {
        b = static_cast<std::byte>(dist(gen));
    }
    
    std::array<std::byte, 12> nonce;
    for (auto& b : nonce) {
        b = static_cast<std::byte>(dist(gen));
    }
    
    // Test data
    std::string plaintext = "Hello, AES-256-GCM! This is a test message.";
    std::vector<std::byte> data;
    data.reserve(plaintext.size());
    for (char c : plaintext) {
        data.push_back(static_cast<std::byte>(c));
    }
    std::vector<std::byte> original_data = data;
    
    // AAD (Additional Authenticated Data)
    std::string aad_str = "Additional authenticated data";
    std::vector<std::byte> aad;
    aad.reserve(aad_str.size());
    for (char c : aad_str) {
        aad.push_back(static_cast<std::byte>(c));
    }
    
    std::array<std::byte, 16> tag;
    
    // Encrypt
    auto ec = psyfer::crypto::aes256_gcm::encrypt_oneshot(
        data, key, nonce, tag, aad
    );
    
    assert(!ec);
    print_hex("Encrypted data", data);
    print_hex("Authentication tag", tag);
    
    // Data should be modified (encrypted)
    assert(data != original_data);
    
    // Decrypt
    ec = psyfer::crypto::aes256_gcm::decrypt_oneshot(
        data, key, nonce, tag, aad
    );
    
    assert(!ec);
    
    // Should match original
    assert(data == original_data);
    std::string decrypted;
    decrypted.reserve(data.size());
    for (std::byte b : data) {
        decrypted.push_back(static_cast<char>(b));
    }
    assert(decrypted == plaintext);
    std::cout << "✓ Encryption/decryption successful" << std::endl;
}

/**
 * @brief Test AES-256-GCM with wrong tag
 */
void test_aes256_gcm_auth_failure() {
    std::cout << "\nTesting AES-256-GCM authentication failure..." << std::endl;
    
    std::array<std::byte, 32> key{};
    std::array<std::byte, 12> nonce{};
    std::array<std::byte, 16> tag{};
    
    std::string plaintext = "Test message";
    std::vector<std::byte> data;
    data.reserve(plaintext.size());
    for (char c : plaintext) {
        data.push_back(static_cast<std::byte>(c));
    }
    
    // Encrypt
    auto ec = psyfer::crypto::aes256_gcm::encrypt_oneshot(
        data, key, nonce, tag, {}
    );
    assert(!ec);
    
    // Corrupt the tag
    tag[0] ^= std::byte(1);
    
    // Decryption should fail
    ec = psyfer::crypto::aes256_gcm::decrypt_oneshot(
        data, key, nonce, tag, {}
    );
    
    assert(ec == psyfer::make_error_code(psyfer::error_code::authentication_failed));
    std::cout << "✓ Authentication failure detected correctly" << std::endl;
}

/**
 * @brief Test AES-256-GCM with different message sizes
 */
void test_aes256_gcm_sizes() {
    std::cout << "\nTesting AES-256-GCM with various sizes..." << std::endl;
    
    std::array<std::byte, 32> key{};
    std::array<std::byte, 12> nonce{};
    
    // Test various sizes
    std::vector<size_t> sizes = {0, 1, 15, 16, 17, 31, 32, 64, 128, 1024};
    
    for (size_t size : sizes) {
        std::vector<std::byte> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<std::byte>(i & 0xff);
        }
        std::vector<std::byte> original = data;
        
        std::array<std::byte, 16> tag;
        
        // Encrypt
        auto ec = psyfer::crypto::aes256_gcm::encrypt_oneshot(
            data, key, nonce, tag, {}
        );
        assert(!ec);
        
        // Decrypt
        ec = psyfer::crypto::aes256_gcm::decrypt_oneshot(
            data, key, nonce, tag, {}
        );
        assert(!ec);
        
        // Verify
        assert(data == original);
        std::cout << "✓ Size " << size << " works correctly" << std::endl;
    }
}

/**
 * @brief Test AES-256-GCM with AAD
 */
void test_aes256_gcm_aad() {
    std::cout << "\nTesting AES-256-GCM with AAD..." << std::endl;
    
    std::array<std::byte, 32> key{};
    std::array<std::byte, 12> nonce{};
    
    std::string plaintext = "Secret message";
    std::vector<std::byte> data;
    data.reserve(plaintext.size());
    for (char c : plaintext) {
        data.push_back(static_cast<std::byte>(c));
    }
    std::vector<std::byte> original = data;
    
    std::string aad_str = "Header: metadata";
    std::vector<std::byte> aad;
    aad.reserve(aad_str.size());
    for (char c : aad_str) {
        aad.push_back(static_cast<std::byte>(c));
    }
    
    std::array<std::byte, 16> tag;
    
    // Encrypt with AAD
    auto ec = psyfer::crypto::aes256_gcm::encrypt_oneshot(
        data, key, nonce, tag, aad
    );
    assert(!ec);
    
    // Try to decrypt with wrong AAD
    std::string wrong_aad_str = "Header: wrong";
    std::vector<std::byte> wrong_aad;
    wrong_aad.reserve(wrong_aad_str.size());
    for (char c : wrong_aad_str) {
        wrong_aad.push_back(static_cast<std::byte>(c));
    }
    
    std::vector<std::byte> data_copy = data;
    ec = psyfer::crypto::aes256_gcm::decrypt_oneshot(
        data_copy, key, nonce, tag, wrong_aad
    );
    assert(ec == psyfer::make_error_code(psyfer::error_code::authentication_failed));
    
    // Decrypt with correct AAD
    ec = psyfer::crypto::aes256_gcm::decrypt_oneshot(
        data, key, nonce, tag, aad
    );
    assert(!ec);
    assert(data == original);
    
    std::cout << "✓ AAD authentication works correctly" << std::endl;
}

/**
 * @brief Test error conditions
 */
void test_aes256_gcm_errors() {
    std::cout << "\nTesting AES-256-GCM error handling..." << std::endl;
    
    std::vector<std::byte> data(16);
    std::array<std::byte, 16> tag;
    psyfer::crypto::aes256_gcm gcm;
    
    // Wrong key size
    std::vector<std::byte> wrong_key(16); // Should be 32
    std::array<std::byte, 12> nonce{};
    
    auto ec = gcm.encrypt(data, wrong_key, nonce, tag, {});
    assert(ec == psyfer::make_error_code(psyfer::error_code::invalid_key_size));
    
    // Wrong nonce size
    std::array<std::byte, 32> key{};
    std::vector<std::byte> wrong_nonce(16); // Should be 12
    
    ec = gcm.encrypt(data, key, wrong_nonce, tag, {});
    assert(ec == psyfer::make_error_code(psyfer::error_code::invalid_nonce_size));
    
    // Wrong tag size
    std::vector<std::byte> wrong_tag(8); // Should be 16
    
    ec = gcm.encrypt(data, key, nonce, wrong_tag, {});
    assert(ec == psyfer::make_error_code(psyfer::error_code::invalid_tag_size));
    
    std::cout << "✓ Error handling works correctly" << std::endl;
}

int main() {
    std::cout << "=== AES-256 Encryption Tests ===" << std::endl;
    
    test_aes256_block();
    test_aes256_gcm_basic();
    test_aes256_gcm_auth_failure();
    test_aes256_gcm_sizes();
    test_aes256_gcm_aad();
    test_aes256_gcm_errors();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}