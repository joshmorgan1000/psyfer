/**
 * @file test_hash_performance.cpp
 * @brief Compare performance of CommonCrypto SHA algorithms
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <CommonCrypto/CommonDigest.h>

/**
 * @brief Benchmark SHA-256 using CommonCrypto
 */
double benchmark_sha256_cc(const std::vector<uint8_t>& data, size_t iterations) {
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < iterations; ++i) {
        CC_SHA256(data.data(), static_cast<CC_LONG>(data.size()), hash);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    return (data.size() * iterations) / (duration / 1000000.0) / (1024 * 1024); // MB/s
}

/**
 * @brief Benchmark SHA-512 using CommonCrypto
 */
double benchmark_sha512_cc(const std::vector<uint8_t>& data, size_t iterations) {
    uint8_t hash[CC_SHA512_DIGEST_LENGTH];
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < iterations; ++i) {
        CC_SHA512(data.data(), static_cast<CC_LONG>(data.size()), hash);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    return (data.size() * iterations) / (duration / 1000000.0) / (1024 * 1024); // MB/s
}


int main() {
    std::cout << "=== Hash Performance Comparison ===" << std::endl;
    std::cout << "CommonCrypto SHA Hardware Acceleration" << std::endl << std::endl;
    
    // Test with different data sizes
    std::vector<size_t> sizes = {64, 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024};
    
    for (size_t size : sizes) {
        std::cout << "Data size: ";
        if (size < 1024) {
            std::cout << size << " bytes" << std::endl;
        } else if (size < 1024 * 1024) {
            std::cout << size / 1024 << " KB" << std::endl;
        } else {
            std::cout << size / (1024 * 1024) << " MB" << std::endl;
        }
        
        // Create test data
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i & 0xff);
        }
        
        // Determine iterations based on data size
        size_t iterations = 1000000 / size;
        if (iterations < 10) iterations = 10;
        if (iterations > 10000) iterations = 10000;
        
        // Benchmark SHA-256
        double sha256_speed = benchmark_sha256_cc(data, iterations);
        std::cout << "  SHA-256 (CommonCrypto): " << std::fixed << std::setprecision(2) 
                  << sha256_speed << " MB/s" << std::endl;
        
        // Benchmark SHA-512
        double sha512_speed = benchmark_sha512_cc(data, iterations);
        std::cout << "  SHA-512 (CommonCrypto): " << std::fixed << std::setprecision(2) 
                  << sha512_speed << " MB/s" << std::endl;
        
        // Compare SHA variants
        std::cout << "  SHA-512 vs SHA-256: " << std::fixed << std::setprecision(2) 
                  << (sha512_speed / sha256_speed) << "x" << std::endl;
        
        std::cout << std::endl;
    }
    
    std::cout << "\nNote: CommonCrypto uses hardware acceleration when available." << std::endl;
    std::cout << "On Apple Silicon, this includes dedicated crypto instructions." << std::endl;
    
    return 0;
}