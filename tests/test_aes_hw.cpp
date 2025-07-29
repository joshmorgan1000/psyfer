/**
 * @file test_aes_hw.cpp
 * @brief Test AES hardware acceleration detection
 */

#include <psyfer.hpp>
#include <iostream>

int main() {
    std::cout << "=== AES Hardware Acceleration Test ===" << std::endl;
    
    // Test the function directly
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    std::cout << "Test binary: ARM64 crypto SHOULD be available" << std::endl;
    #endif
    
    bool hw_available = psyfer::crypto::aes_ni_available();
    std::cout << "AES hardware acceleration available: " << (hw_available ? "YES" : "NO") << std::endl;
    
    // Debug: Check what's defined
    #if defined(__aarch64__)
    std::cout << "__aarch64__ is defined" << std::endl;
    #endif
    #if defined(__ARM_FEATURE_CRYPTO)
    std::cout << "__ARM_FEATURE_CRYPTO is defined" << std::endl;
    #endif
    #if defined(__AES__)
    std::cout << "__AES__ is defined" << std::endl;
    #endif
    
    #ifdef __aarch64__
    std::cout << "Architecture: ARM64" << std::endl;
    #ifdef __ARM_FEATURE_CRYPTO
    std::cout << "ARM crypto extensions: ENABLED" << std::endl;
    #else
    std::cout << "ARM crypto extensions: DISABLED" << std::endl;
    #endif
    #endif
    
    #ifdef __x86_64__
    std::cout << "Architecture: x86_64" << std::endl;
    #ifdef __AES__
    std::cout << "AES-NI: ENABLED" << std::endl;
    #else
    std::cout << "AES-NI: DISABLED" << std::endl;
    #endif
    #endif
    
    // Quick performance test
    auto key = psyfer::utils::aes256_key::generate();
    if (!key.has_value()) {
        std::cerr << "Failed to generate key" << std::endl;
        return 1;
    }
    
    auto nonce = psyfer::utils::secure_random::generate_nonce<12>();
    if (!nonce.has_value()) {
        std::cerr << "Failed to generate nonce" << std::endl;
        return 1;
    }
    
    std::vector<std::byte> data(1024);
    std::array<std::byte, 16> tag;
    
    // Time a single encryption
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 10000; ++i) {
        auto ec = psyfer::crypto::aes256_gcm::encrypt_oneshot(
            data, key->span(), nonce.value(), tag, {}
        );
        if (ec) {
            std::cerr << "Encryption failed: " << ec.message() << std::endl;
            return 1;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double mb_per_sec = (10000.0 * 1024.0 / 1024.0 / 1024.0) / (duration.count() / 1000000.0);
    std::cout << "\nPerformance: " << mb_per_sec << " MB/s" << std::endl;
    
    return 0;
}