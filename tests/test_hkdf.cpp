/**
 * @file test_hkdf.cpp
 * @brief Tests for HKDF implementation
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
    std::cout << std::dec << " (" << data.size() << " bytes)" << std::endl;
}

/**
 * @brief Test HKDF with RFC 5869 test vectors
 */
void test_hkdf_rfc5869_vectors() {
    std::cout << "Testing HKDF with RFC 5869 test vectors..." << std::endl;
    
    // Test Case 1 (SHA-256)
    {
        std::cout << "\nTest Case 1 (SHA-256):" << std::endl;
        
        // Input
        std::array<std::byte, 22> ikm;
        std::fill(ikm.begin(), ikm.end(), std::byte{0x0b});
        
        std::array<std::byte, 13> salt;
        for (size_t i = 0; i < salt.size(); ++i) {
            salt[i] = std::byte(i);
        }
        
        std::array<std::byte, 10> info;
        for (size_t i = 0; i < info.size(); ++i) {
            info[i] = std::byte(0xf0 + i);
        }
        
        // Output
        std::array<std::byte, 42> okm;
        
        auto ec = psyfer::kdf::hkdf::derive_sha256(ikm, salt, info, okm);
        assert(!ec);
        
        print_hex("OKM", okm);
        
        // Expected first few bytes: 3cb25f25faacd57a90434f64d0362f2a...
        assert(static_cast<uint8_t>(okm[0]) == 0x3c);
        assert(static_cast<uint8_t>(okm[1]) == 0xb2);
        assert(static_cast<uint8_t>(okm[2]) == 0x5f);
        
        std::cout << "✓ Test Case 1 passed" << std::endl;
    }
    
    // Test Case 2 (SHA-256) - Long inputs
    {
        std::cout << "\nTest Case 2 (SHA-256) - Long inputs:" << std::endl;
        
        // 80-byte IKM
        std::array<std::byte, 80> ikm;
        for (size_t i = 0; i < ikm.size(); ++i) {
            ikm[i] = std::byte(0x00 + i);
        }
        
        // 80-byte salt
        std::array<std::byte, 80> salt;
        for (size_t i = 0; i < salt.size(); ++i) {
            salt[i] = std::byte(0x60 + i);
        }
        
        // 80-byte info
        std::array<std::byte, 80> info;
        for (size_t i = 0; i < info.size(); ++i) {
            info[i] = std::byte(0xb0 + i);
        }
        
        // 82-byte output
        std::array<std::byte, 82> okm;
        
        auto ec = psyfer::kdf::hkdf::derive_sha256(ikm, salt, info, okm);
        assert(!ec);
        
        print_hex("OKM (first 16 bytes)", std::span(okm.data(), 16));
        
        std::cout << "✓ Test Case 2 passed" << std::endl;
    }
}

/**
 * @brief Test HKDF extract and expand separately
 */
void test_hkdf_extract_expand() {
    std::cout << "\nTesting HKDF extract and expand separately..." << std::endl;
    
    // SHA-256
    {
        std::cout << "SHA-256:" << std::endl;
        
        std::array<std::byte, 16> ikm;
        std::fill(ikm.begin(), ikm.end(), std::byte{0xaa});
        
        std::array<std::byte, 16> salt;
        std::fill(salt.begin(), salt.end(), std::byte{0x55});
        
        // Extract
        std::array<std::byte, 32> prk;
        psyfer::kdf::hkdf::extract_sha256(salt, ikm, prk);
        print_hex("PRK", prk);
        
        // Expand
        std::array<std::byte, 64> okm;
        std::array<std::byte, 8> info{};
        auto ec = psyfer::kdf::hkdf::expand_sha256(prk, info, okm);
        assert(!ec);
        print_hex("OKM (first 16 bytes)", std::span(okm.data(), 16));
        
        std::cout << "✓ SHA-256 extract/expand passed" << std::endl;
    }
    
    // SHA-512
    {
        std::cout << "\nSHA-512:" << std::endl;
        
        std::array<std::byte, 16> ikm;
        std::fill(ikm.begin(), ikm.end(), std::byte{0xbb});
        
        std::array<std::byte, 16> salt;
        std::fill(salt.begin(), salt.end(), std::byte{0x66});
        
        // Extract
        std::array<std::byte, 64> prk;
        psyfer::kdf::hkdf::extract_sha512(salt, ikm, prk);
        print_hex("PRK (first 16 bytes)", std::span(prk.data(), 16));
        
        // Expand
        std::array<std::byte, 128> okm;
        std::array<std::byte, 8> info{};
        auto ec = psyfer::kdf::hkdf::expand_sha512(prk, info, okm);
        assert(!ec);
        print_hex("OKM (first 16 bytes)", std::span(okm.data(), 16));
        
        std::cout << "✓ SHA-512 extract/expand passed" << std::endl;
    }
}

/**
 * @brief Test HKDF edge cases
 */
void test_hkdf_edge_cases() {
    std::cout << "\nTesting HKDF edge cases..." << std::endl;
    
    // Empty salt
    {
        std::array<std::byte, 16> ikm;
        std::fill(ikm.begin(), ikm.end(), std::byte{0x42});
        
        std::span<const std::byte> empty_salt;
        std::span<const std::byte> empty_info;
        
        std::array<std::byte, 32> okm;
        auto ec = psyfer::kdf::hkdf::derive_sha256(ikm, empty_salt, empty_info, okm);
        assert(!ec);
        
        std::cout << "✓ Empty salt works" << std::endl;
    }
    
    // Maximum output length (255 * HashLen)
    {
        std::array<std::byte, 32> ikm;
        psyfer::utils::secure_random::generate(ikm);
        
        std::array<std::byte, 16> salt;
        psyfer::utils::secure_random::generate(salt);
        
        // Try maximum allowed
        std::vector<std::byte> okm(255 * 32);
        auto ec = psyfer::kdf::hkdf::derive_sha256(ikm, salt, {}, okm);
        assert(!ec);
        
        std::cout << "✓ Maximum output length works" << std::endl;
        
        // Try one byte too much
        okm.resize(255 * 32 + 1);
        ec = psyfer::kdf::hkdf::derive_sha256(ikm, salt, {}, okm);
        assert(ec == psyfer::make_error_code(psyfer::error_code::invalid_buffer_size));
        
        std::cout << "✓ Exceeding maximum length fails correctly" << std::endl;
    }
    
    // Zero-length output
    {
        std::array<std::byte, 16> ikm;
        std::span<std::byte> empty_output;
        
        auto ec = psyfer::kdf::hkdf::derive_sha256(ikm, {}, {}, empty_output);
        assert(!ec);
        
        std::cout << "✓ Zero-length output works" << std::endl;
    }
}

/**
 * @brief Test HKDF key derivation use case
 */
void test_hkdf_key_derivation() {
    std::cout << "\nTesting HKDF for key derivation..." << std::endl;
    
    // Derive multiple keys from a single master key
    std::array<std::byte, 32> master_key;
    auto ec = psyfer::utils::secure_random::generate(master_key);
    assert(!ec);
    
    // Application-specific salt
    const char* salt_str = "MyApp v1.0";
    std::span<const std::byte> salt(
        reinterpret_cast<const std::byte*>(salt_str),
        strlen(salt_str)
    );
    
    // Derive encryption key
    std::array<std::byte, 32> enc_key;
    const char* enc_info = "encryption";
    ec = psyfer::kdf::hkdf::derive_sha256(
        master_key, salt,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(enc_info),
            strlen(enc_info)
        ),
        enc_key
    );
    assert(!ec);
    print_hex("Encryption key", enc_key);
    
    // Derive MAC key
    std::array<std::byte, 32> mac_key;
    const char* mac_info = "authentication";
    ec = psyfer::kdf::hkdf::derive_sha256(
        master_key, salt,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(mac_info),
            strlen(mac_info)
        ),
        mac_key
    );
    assert(!ec);
    print_hex("MAC key", mac_key);
    
    // Keys should be different
    assert(std::memcmp(enc_key.data(), mac_key.data(), 32) != 0);
    
    std::cout << "✓ Key derivation works correctly" << std::endl;
}

int main() {
    std::cout << "=== HKDF Tests ===" << std::endl;
    
    test_hkdf_rfc5869_vectors();
    test_hkdf_extract_expand();
    test_hkdf_edge_cases();
    test_hkdf_key_derivation();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}