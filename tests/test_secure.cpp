/**
 * @file test_secure.cpp
 * @brief Tests for secure utilities
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <thread>
#include <chrono>

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
 * @brief Test secure random generation
 */
void test_secure_random() {
    std::cout << "Testing secure random generation..." << std::endl;
    
    // Test basic buffer fill
    std::array<std::byte, 32> buffer{};
    auto ec = psyfer::utils::secure_random::generate(buffer);
    assert(!ec);
    print_hex("Random 32 bytes", buffer);
    
    // Check that it's not all zeros
    bool all_zeros = true;
    for (auto b : buffer) {
        if (b != std::byte{0}) {
            all_zeros = false;
            break;
        }
    }
    assert(!all_zeros);
    std::cout << "✓ Random data is not all zeros" << std::endl;
    
    // Test generating different values
    std::array<std::byte, 32> buffer2{};
    ec = psyfer::utils::secure_random::generate(buffer2);
    assert(!ec);
    
    // Should be different (extremely high probability)
    assert(std::memcmp(buffer.data(), buffer2.data(), 32) != 0);
    std::cout << "✓ Multiple calls produce different values" << std::endl;
    
    // Test typed generation
    auto result = psyfer::utils::secure_random::generate<uint64_t>();
    assert(result.has_value());
    std::cout << "✓ Random uint64_t: " << result.value() << std::endl;
    
    // Test key generation
    auto key_result = psyfer::utils::secure_random::generate_key<32>();
    assert(key_result.has_value());
    print_hex("Generated 256-bit key", key_result.value());
    
    // Test nonce generation
    auto nonce_result = psyfer::utils::secure_random::generate_nonce<12>();
    assert(nonce_result.has_value());
    print_hex("Generated 96-bit nonce", nonce_result.value());
}

/**
 * @brief Test secure buffer
 */
void test_secure_buffer() {
    std::cout << "\nTesting secure buffer..." << std::endl;
    
    // Create secure buffer
    psyfer::utils::secure_buffer<32> key_buffer;
    
    // Should be zero-initialized
    bool all_zeros = true;
    for (auto b : key_buffer.span()) {
        if (b != std::byte{0}) {
            all_zeros = false;
            break;
        }
    }
    assert(all_zeros);
    std::cout << "✓ Buffer is zero-initialized" << std::endl;
    
    // Fill with random data
    auto random_result = psyfer::utils::secure_random::generate(key_buffer.span());
    assert(!random_result);
    print_hex("Secure buffer contents", key_buffer.span());
    
    // Test clear
    key_buffer.clear();
    all_zeros = true;
    for (auto b : key_buffer.span()) {
        if (b != std::byte{0}) {
            all_zeros = false;
            break;
        }
    }
    assert(all_zeros);
    std::cout << "✓ Buffer cleared successfully" << std::endl;
    
    // Test fill
    std::array<std::byte, 32> source{};
    for (size_t i = 0; i < 32; ++i) {
        source[i] = static_cast<std::byte>(i);
    }
    key_buffer.fill(source);
    
    assert(std::memcmp(key_buffer.data(), source.data(), 32) == 0);
    std::cout << "✓ Buffer filled correctly" << std::endl;
    
    // Test move operations
    psyfer::utils::secure_buffer<32> moved_buffer(std::move(key_buffer));
    assert(std::memcmp(moved_buffer.data(), source.data(), 32) == 0);
    std::cout << "✓ Move constructor works" << std::endl;
}

/**
 * @brief Test secure allocator
 */
void test_secure_allocator() {
    std::cout << "\nTesting secure allocator..." << std::endl;
    
    // Test secure vector
    {
        psyfer::utils::secure_vector<std::byte> vec;
        vec.resize(64);
        
        // Fill with sensitive data
        for (size_t i = 0; i < 64; ++i) {
            vec[i] = static_cast<std::byte>(i ^ 0xAA);
        }
        
        std::cout << "✓ Secure vector allocated and filled" << std::endl;
        
        // Vector will be securely cleared on destruction
    }
    
    // Test secure string
    {
        psyfer::utils::secure_string password = "SuperSecretPassword123!";
        assert(password.size() == 23);
        std::cout << "✓ Secure string created" << std::endl;
        
        // String will be securely cleared on destruction
    }
}

/**
 * @brief Test secure memory operations
 */
void test_secure_memory_ops() {
    std::cout << "\nTesting secure memory operations..." << std::endl;
    
    // Test secure clear
    char sensitive_data[32];
    std::memset(sensitive_data, 0xFF, 32);
    
    psyfer::utils::secure_clear(sensitive_data, 32);
    
    bool all_zeros = true;
    for (int i = 0; i < 32; ++i) {
        if (sensitive_data[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    assert(all_zeros);
    std::cout << "✓ Secure clear works" << std::endl;
    
    // Test secure compare
    uint8_t data1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t data2[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t data3[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17};
    
    assert(psyfer::utils::secure_compare(data1, data2, 16));
    assert(!psyfer::utils::secure_compare(data1, data3, 16));
    std::cout << "✓ Secure compare works" << std::endl;
    
    // Test timing resistance (basic check)
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100000; ++i) {
        psyfer::utils::secure_compare(data1, data2, 16);
    }
    auto equal_time = std::chrono::high_resolution_clock::now() - start;
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100000; ++i) {
        psyfer::utils::secure_compare(data1, data3, 16);
    }
    auto not_equal_time = std::chrono::high_resolution_clock::now() - start;
    
    // Times should be similar (within 20%)
    auto ratio = static_cast<double>(equal_time.count()) / not_equal_time.count();
    assert(ratio > 0.8 && ratio < 1.2);
    std::cout << "✓ Secure compare appears to be constant-time" << std::endl;
}

/**
 * @brief Test integration with crypto operations
 */
void test_crypto_integration() {
    std::cout << "\nTesting integration with crypto operations..." << std::endl;
    
    // Generate secure key and nonce
    auto key_result = psyfer::utils::secure_random::generate_key<32>();
    assert(key_result.has_value());
    
    auto nonce_result = psyfer::utils::secure_random::generate_nonce<12>();
    assert(nonce_result.has_value());
    
    // Use secure buffer for sensitive data
    psyfer::utils::secure_buffer<32> key_buffer;
    key_buffer.fill(key_result.value());
    
    // Encrypt some data
    std::string plaintext = "Secret message";
    std::vector<std::byte> data;
    data.reserve(plaintext.size());
    for (char c : plaintext) {
        data.push_back(static_cast<std::byte>(c));
    }
    
    std::array<std::byte, 16> tag;
    
    auto ec = psyfer::crypto::aes256_gcm::encrypt_oneshot(
        data, 
        key_buffer.span(), 
        nonce_result.value(), 
        tag, 
        {}
    );
    
    assert(!ec);
    std::cout << "✓ Encryption with secure key successful" << std::endl;
    
    // Decrypt
    ec = psyfer::crypto::aes256_gcm::decrypt_oneshot(
        data,
        key_buffer.span(),
        nonce_result.value(),
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
    std::cout << "✓ Decryption with secure key successful" << std::endl;
}

int main() {
    std::cout << "=== Secure Utilities Tests ===" << std::endl;
    
    test_secure_random();
    test_secure_buffer();
    test_secure_allocator();
    test_secure_memory_ops();
    test_crypto_integration();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}