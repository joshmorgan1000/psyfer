/**
 * @file test_chacha20.cpp
 * @brief Tests for ChaCha20-Poly1305 AEAD
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>

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
 * @brief Test ChaCha20 stream cipher
 */
void test_chacha20_stream() {
    std::cout << "Testing ChaCha20 stream cipher..." << std::endl;
    
    // Test vector from RFC 8439
    std::array<std::byte, 32> key;
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::byte>(i);
    }
    
    std::array<std::byte, 12> nonce = {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x09},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x4a},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
    };
    
    // Test data
    std::string plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::vector<std::byte> data;
    data.reserve(plaintext.size());
    for (char c : plaintext) {
        data.push_back(static_cast<std::byte>(c));
    }
    
    // Encrypt
    psyfer::crypto::chacha20::crypt(data, key, nonce, 1);
    print_hex("Encrypted", data);
    
    // Decrypt (ChaCha20 is symmetric)
    psyfer::crypto::chacha20::crypt(data, key, nonce, 1);
    
    // Verify
    std::string decrypted;
    decrypted.reserve(data.size());
    for (std::byte b : data) {
        decrypted.push_back(static_cast<char>(b));
    }
    
    assert(decrypted == plaintext);
    std::cout << "✓ ChaCha20 stream cipher works correctly" << std::endl;
}

/**
 * @brief Test Poly1305 MAC
 */
void test_poly1305() {
    std::cout << "\nTesting Poly1305 MAC..." << std::endl;
    
    // Test vector
    std::array<std::byte, 32> key;
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<std::byte>(i + 1);
    }
    
    std::string message = "Cryptographic Forum Research Group";
    std::vector<std::byte> data;
    data.reserve(message.size());
    for (char c : message) {
        data.push_back(static_cast<std::byte>(c));
    }
    
    // Compute MAC
    std::array<std::byte, 16> tag;
    psyfer::crypto::poly1305::auth(data, key, tag);
    print_hex("Poly1305 tag", tag);
    
    // Test incremental API
    psyfer::crypto::poly1305 poly;
    poly.init(key);
    poly.update(data);
    
    std::array<std::byte, 16> tag2;
    poly.finalize(tag2);
    
    assert(std::memcmp(tag.data(), tag2.data(), 16) == 0);
    std::cout << "✓ Poly1305 one-shot and incremental produce same result" << std::endl;
}

/**
 * @brief Test ChaCha20-Poly1305 AEAD
 */
void test_chacha20_poly1305() {
    std::cout << "\nTesting ChaCha20-Poly1305 AEAD..." << std::endl;
    
    // Generate key and nonce
    auto key = psyfer::utils::chacha20_key::generate();
    assert(key.has_value());
    
    auto nonce = psyfer::utils::secure_random::generate_nonce<12>();
    assert(nonce.has_value());
    
    // Test data
    std::string plaintext = "Hello, ChaCha20-Poly1305!";
    std::vector<std::byte> data;
    data.reserve(plaintext.size());
    for (char c : plaintext) {
        data.push_back(static_cast<std::byte>(c));
    }
    
    // AAD
    std::string aad_str = "Additional data";
    std::vector<std::byte> aad;
    aad.reserve(aad_str.size());
    for (char c : aad_str) {
        aad.push_back(static_cast<std::byte>(c));
    }
    
    // Encrypt
    std::array<std::byte, 16> tag;
    auto ec = psyfer::crypto::chacha20_poly1305::encrypt_oneshot(
        data,
        key->span(),
        nonce.value(),
        tag,
        aad
    );
    assert(!ec);
    
    print_hex("Encrypted data", data);
    print_hex("Authentication tag", tag);
    
    // Decrypt
    ec = psyfer::crypto::chacha20_poly1305::decrypt_oneshot(
        data,
        key->span(),
        nonce.value(),
        tag,
        aad
    );
    assert(!ec);
    
    // Verify
    std::string decrypted;
    decrypted.reserve(data.size());
    for (std::byte b : data) {
        decrypted.push_back(static_cast<char>(b));
    }
    
    assert(decrypted == plaintext);
    std::cout << "✓ Encryption/decryption successful" << std::endl;
}

/**
 * @brief Test authentication failure
 */
void test_authentication_failure() {
    std::cout << "\nTesting ChaCha20-Poly1305 authentication failure..." << std::endl;
    
    auto key = psyfer::utils::chacha20_key::generate();
    assert(key.has_value());
    
    auto nonce = psyfer::utils::secure_random::generate_nonce<12>();
    assert(nonce.has_value());
    
    std::vector<std::byte> data = {
        std::byte{0x48}, std::byte{0x65}, std::byte{0x6c}, std::byte{0x6c}, std::byte{0x6f}
    };
    
    std::array<std::byte, 16> tag;
    
    // Encrypt
    auto ec = psyfer::crypto::chacha20_poly1305::encrypt_oneshot(
        data,
        key->span(),
        nonce.value(),
        tag,
        {}
    );
    assert(!ec);
    
    // Corrupt tag
    tag[0] ^= std::byte{0xFF};
    
    // Try to decrypt
    ec = psyfer::crypto::chacha20_poly1305::decrypt_oneshot(
        data,
        key->span(),
        nonce.value(),
        tag,
        {}
    );
    
    assert(ec == psyfer::make_error_code(psyfer::error_code::authentication_failed));
    std::cout << "✓ Authentication failure detected correctly" << std::endl;
}

/**
 * @brief Test with various data sizes
 */
void test_various_sizes() {
    std::cout << "\nTesting ChaCha20-Poly1305 with various sizes..." << std::endl;
    
    auto key = psyfer::utils::chacha20_key::generate();
    assert(key.has_value());
    
    // Test different sizes
    std::vector<size_t> sizes = {0, 1, 15, 16, 17, 31, 32, 64, 128, 1024};
    
    for (size_t size : sizes) {
        auto nonce = psyfer::utils::secure_random::generate_nonce<12>();
        assert(nonce.has_value());
        
        // Create test data
        std::vector<std::byte> original(size);
        for (size_t i = 0; i < size; ++i) {
            original[i] = static_cast<std::byte>(i & 0xFF);
        }
        
        std::vector<std::byte> data = original;
        std::array<std::byte, 16> tag;
        
        // Encrypt
        auto ec = psyfer::crypto::chacha20_poly1305::encrypt_oneshot(
            data,
            key->span(),
            nonce.value(),
            tag,
            {}
        );
        assert(!ec);
        
        // Decrypt
        ec = psyfer::crypto::chacha20_poly1305::decrypt_oneshot(
            data,
            key->span(),
            nonce.value(),
            tag,
            {}
        );
        assert(!ec);
        
        // Verify
        assert(data == original);
        std::cout << "✓ Size " << size << " works correctly" << std::endl;
    }
}

/**
 * @brief Test error handling
 */
void test_error_handling() {
    std::cout << "\nTesting ChaCha20-Poly1305 error handling..." << std::endl;
    
    psyfer::crypto::chacha20_poly1305 cipher;
    std::vector<std::byte> data(32);
    std::array<std::byte, 16> tag;
    
    // Wrong key size
    std::vector<std::byte> wrong_key(16);
    auto ec = cipher.encrypt(data, wrong_key, 
                            std::span<const std::byte>(wrong_key.data(), 12), 
                            tag, {});
    assert(ec == psyfer::make_error_code(psyfer::error_code::invalid_key_size));
    
    // Wrong nonce size
    std::array<std::byte, 32> key{};
    std::vector<std::byte> wrong_nonce(8);
    ec = cipher.encrypt(data, key, wrong_nonce, tag, {});
    assert(ec == psyfer::make_error_code(psyfer::error_code::invalid_nonce_size));
    
    // Wrong tag size
    std::array<std::byte, 12> nonce{};
    std::vector<std::byte> wrong_tag(8);
    ec = cipher.encrypt(data, key, nonce, wrong_tag, {});
    assert(ec == psyfer::make_error_code(psyfer::error_code::invalid_tag_size));
    
    std::cout << "✓ Error handling works correctly" << std::endl;
}

/**
 * @brief Test performance comparison with AES
 */
void test_performance_comparison() {
    std::cout << "\nComparing ChaCha20-Poly1305 vs AES-256-GCM performance..." << std::endl;
    
    const size_t data_size = 1024 * 1024; // 1 MB
    const size_t iterations = 100;
    
    auto key = psyfer::utils::secure_key_256::generate();
    assert(key.has_value());
    
    auto nonce = psyfer::utils::secure_random::generate_nonce<12>();
    assert(nonce.has_value());
    
    std::vector<std::byte> data(data_size);
    psyfer::utils::secure_random::generate(data);
    
    // Time ChaCha20-Poly1305
    auto chacha_data = data;
    std::array<std::byte, 16> chacha_tag;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        psyfer::crypto::chacha20_poly1305::encrypt_oneshot(
            chacha_data, key->span(), nonce.value(), chacha_tag, {}
        );
    }
    auto chacha_time = std::chrono::high_resolution_clock::now() - start;
    
    // Time AES-256-GCM
    auto aes_data = data;
    std::array<std::byte, 16> aes_tag;
    
    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        psyfer::crypto::aes256_gcm::encrypt_oneshot(
            aes_data, key->span(), nonce.value(), aes_tag, {}
        );
    }
    auto aes_time = std::chrono::high_resolution_clock::now() - start;
    
    auto chacha_ms = std::chrono::duration_cast<std::chrono::milliseconds>(chacha_time).count();
    auto aes_ms = std::chrono::duration_cast<std::chrono::milliseconds>(aes_time).count();
    
    std::cout << "ChaCha20-Poly1305: " << chacha_ms << " ms" << std::endl;
    std::cout << "AES-256-GCM: " << aes_ms << " ms" << std::endl;
    
    double chacha_mbps = (data_size * iterations / 1024.0 / 1024.0) / (chacha_ms / 1000.0);
    double aes_mbps = (data_size * iterations / 1024.0 / 1024.0) / (aes_ms / 1000.0);
    
    std::cout << "ChaCha20-Poly1305: " << std::fixed << std::setprecision(2) 
              << chacha_mbps << " MB/s" << std::endl;
    std::cout << "AES-256-GCM: " << std::fixed << std::setprecision(2) 
              << aes_mbps << " MB/s" << std::endl;
}

int main() {
    std::cout << "=== ChaCha20-Poly1305 Tests ===" << std::endl;
    
    test_chacha20_stream();
    test_poly1305();
    test_chacha20_poly1305();
    test_authentication_failure();
    test_various_sizes();
    test_error_handling();
    test_performance_comparison();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}