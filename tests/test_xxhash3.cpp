/**
 * @file test_xxhash3.cpp
 * @brief Tests for xxHash3 implementation
 */

#include <psyfer.hpp>
#include <psyfer/hash/xxhash3.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <chrono>
#include <vector>
#include <cstring>

/**
 * @brief Print hash value
 */
void print_hash64(const std::string& label, uint64_t hash) {
    std::cout << label << ": " << std::hex << std::setw(16) << std::setfill('0') 
              << hash << std::dec << std::endl;
}

void print_hash128(const std::string& label, psyfer::hash::xxhash3_128::hash128 hash) {
    std::cout << label << ": " << std::hex << std::setw(16) << std::setfill('0') 
              << hash.high << std::setw(16) << std::setfill('0') << hash.low 
              << std::dec << std::endl;
}

/**
 * @brief Test xxHash3 32-bit variant
 */
void test_xxhash3_32bit() {
    std::cout << "Testing xxHash3 32-bit variant..." << std::endl;
    
    // Test empty input
    {
        std::vector<std::byte> empty;
        uint32_t hash = psyfer::hash::xxhash3_32::hash(empty, 0);
        std::cout << "Empty hash (32-bit): " << std::hex << hash << std::dec << std::endl;
    }
    
    // Test simple string
    {
        std::string test = "Hello, xxHash3-32!";
        uint32_t hash1 = psyfer::hash::xxhash3_32::hash(test, 0);
        uint32_t hash2 = psyfer::hash::xxhash3_32::hash(test, 0);
        std::cout << "String hash (32-bit): " << std::hex << hash1 << std::dec << std::endl;
        assert(hash1 == hash2);  // Deterministic
        
        // Different seed
        uint32_t hash3 = psyfer::hash::xxhash3_32::hash(test, 12345);
        std::cout << "With different seed: " << std::hex << hash3 << std::dec << std::endl;
        if (hash1 == hash3) {
            std::cout << "Warning: seed not affecting hash for size " << test.size() << std::endl;
        }
    }
    
    std::cout << "✓ 32-bit variant tests passed" << std::endl;
}

/**
 * @brief Test basic xxHash3 functionality
 */
void test_xxhash3_basic() {
    std::cout << "\nTesting basic xxHash3 64-bit functionality..." << std::endl;
    
    // Test empty input
    {
        std::vector<std::byte> empty;
        uint64_t hash = psyfer::hash::xxhash3_64::hash(empty, 0);
        print_hash64("Empty hash", hash);
        assert(hash == 0x2D06800538D394C2ULL);  // Known value for empty input
    }
    
    // Test simple string
    {
        std::string test = "Hello, xxHash3!";
        uint64_t hash = psyfer::hash::xxhash3_64::hash(test, 0);
        print_hash64("String hash", hash);
        
        // Hash should be deterministic
        uint64_t hash2 = psyfer::hash::xxhash3_64::hash(test, 0);
        assert(hash == hash2);
    }
    
    // Test with seed
    {
        std::string test = "Hello, xxHash3!";
        uint64_t hash1 = psyfer::hash::xxhash3_64::hash(test, 0);
        uint64_t hash2 = psyfer::hash::xxhash3_64::hash(test, 12345);
        print_hash64("With seed 0", hash1);
        print_hash64("With seed 12345", hash2);
        assert(hash1 != hash2);  // Different seeds should produce different hashes
    }
    
    std::cout << "✓ Basic functionality tests passed" << std::endl;
}

/**
 * @brief Test xxHash3 streaming API
 */
void test_xxhash3_streaming() {
    std::cout << "\nTesting xxHash3 streaming API..." << std::endl;
    
    std::string test_data = "The quick brown fox jumps over the lazy dog";
    
    // One-shot hash
    uint64_t oneshot = psyfer::hash::xxhash3_64::hash(test_data, 0);
    print_hash64("One-shot", oneshot);
    
    // Streaming hash - full update
    psyfer::hash::xxhash3_64::hasher hasher1(0);
    hasher1.update(test_data);
    uint64_t streaming1 = hasher1.finalize();
    print_hash64("Streaming (full)", streaming1);
    assert(oneshot == streaming1);
    
    // Streaming hash - partial updates
    psyfer::hash::xxhash3_64::hasher hasher2(0);
    hasher2.update(std::string_view(test_data).substr(0, 10));
    hasher2.update(std::string_view(test_data).substr(10, 15));
    hasher2.update(std::string_view(test_data).substr(25));
    uint64_t streaming2 = hasher2.finalize();
    print_hash64("Streaming (parts)", streaming2);
    assert(oneshot == streaming2);
    
    // Test reset
    hasher2.reset(0);
    hasher2.update(test_data);
    uint64_t streaming3 = hasher2.finalize();
    assert(oneshot == streaming3);
    
    std::cout << "✓ Streaming API tests passed" << std::endl;
}

/**
 * @brief Test xxHash3 128-bit variant
 */
void test_xxhash3_128() {
    std::cout << "\nTesting xxHash3 128-bit variant..." << std::endl;
    
    // Test empty input
    {
        std::vector<std::byte> empty;
        auto hash = psyfer::hash::xxhash3_128::hash(empty, 0);
        print_hash128("Empty hash", hash);
    }
    
    // Test simple string
    {
        std::string test = "Hello, xxHash3-128!";
        auto hash = psyfer::hash::xxhash3_128::hash(test, 0);
        print_hash128("String hash", hash);
        
        // Should be deterministic
        auto hash2 = psyfer::hash::xxhash3_128::hash(test, 0);
        assert(hash == hash2);
    }
    
    // Test streaming
    {
        std::string test_data = "The quick brown fox jumps over the lazy dog";
        
        auto oneshot = psyfer::hash::xxhash3_128::hash(test_data, 0);
        
        psyfer::hash::xxhash3_128::hasher hasher(0);
        hasher.update(test_data);
        auto streaming = hasher.finalize();
        
        assert(oneshot == streaming);
    }
    
    std::cout << "✓ 128-bit variant tests passed" << std::endl;
}

/**
 * @brief Test different input sizes
 */
void test_xxhash3_sizes() {
    std::cout << "\nTesting different input sizes..." << std::endl;
    
    // Test various sizes to exercise different code paths
    std::vector<size_t> sizes = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129,
        239, 240, 241, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
        4095, 4096, 4097, 8191, 8192, 8193
    };
    
    for (size_t size : sizes) {
        std::vector<std::byte> data(size);
        // Fill with pattern
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<std::byte>(i & 0xFF);
        }
        
        // Hash with one-shot
        uint64_t hash1 = psyfer::hash::xxhash3_64::hash(data, 0);
        
        // Hash with streaming
        psyfer::hash::xxhash3_64::hasher hasher(0);
        hasher.update(data);
        uint64_t hash2 = hasher.finalize();
        
        if (hash1 != hash2) {
            std::cout << "Mismatch at size " << size << std::endl;
            print_hash64("One-shot", hash1);
            print_hash64("Streaming", hash2);
        }
        assert(hash1 == hash2);
    }
    
    std::cout << "✓ All sizes produce consistent results" << std::endl;
}

/**
 * @brief Test hash quality (basic avalanche test)
 */
void test_xxhash3_quality() {
    std::cout << "\nTesting hash quality..." << std::endl;
    
    // Test that single bit changes produce very different hashes
    std::vector<std::byte> data(64);
    for (size_t i = 0; i < 64; ++i) {
        data[i] = static_cast<std::byte>(i);
    }
    
    uint64_t base_hash = psyfer::hash::xxhash3_64::hash(data, 0);
    
    int total_bit_diffs = 0;
    for (size_t byte_idx = 0; byte_idx < data.size(); ++byte_idx) {
        for (int bit = 0; bit < 8; ++bit) {
            // Flip one bit
            data[byte_idx] ^= static_cast<std::byte>(1 << bit);
            uint64_t modified_hash = psyfer::hash::xxhash3_64::hash(data, 0);
            data[byte_idx] ^= static_cast<std::byte>(1 << bit);  // Flip back
            
            // Count bit differences
            uint64_t diff = base_hash ^ modified_hash;
            int bit_count = __builtin_popcountll(diff);
            total_bit_diffs += bit_count;
        }
    }
    
    double avg_bit_diff = static_cast<double>(total_bit_diffs) / (data.size() * 8);
    std::cout << "Average bit differences on single bit flip: " << avg_bit_diff << std::endl;
    
    // Good hash should change about half the bits (32 out of 64)
    assert(avg_bit_diff > 25 && avg_bit_diff < 39);
    
    std::cout << "✓ Hash quality test passed" << std::endl;
}

/**
 * @brief Benchmark xxHash3 performance
 */
void benchmark_xxhash3() {
    std::cout << "\nBenchmarking xxHash3 performance..." << std::endl;
    
    const size_t MB = 1024 * 1024;
    std::vector<std::byte> data(100 * MB);
    
    // Fill with pseudo-random data
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>((i * 7919) & 0xFF);
    }
    
    // Benchmark 32-bit version
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        uint32_t hash = psyfer::hash::xxhash3_32::hash(data, 0);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        double throughput = (data.size() / (1024.0 * 1024.0)) / (duration / 1000000.0);
        std::cout << "xxHash3-32 throughput: " << std::fixed << std::setprecision(2) 
                  << throughput << " MB/s" << std::endl;
        std::cout << "Hash: " << std::hex << hash << std::dec << std::endl;
    }
    
    // Benchmark 64-bit version
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        uint64_t hash = psyfer::hash::xxhash3_64::hash(data, 0);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        double throughput = (data.size() / (1024.0 * 1024.0)) / (duration / 1000000.0);
        std::cout << "xxHash3-64 throughput: " << std::fixed << std::setprecision(2) 
                  << throughput << " MB/s" << std::endl;
        print_hash64("Hash", hash);
    }
    
    // Benchmark 128-bit version
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        auto hash = psyfer::hash::xxhash3_128::hash(data, 0);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        double throughput = (data.size() / (1024.0 * 1024.0)) / (duration / 1000000.0);
        std::cout << "xxHash3-128 throughput: " << std::fixed << std::setprecision(2) 
                  << throughput << " MB/s" << std::endl;
        print_hash128("Hash", hash);
    }
    
    // Compare with SHA-256 for reference
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        psyfer::hash::sha256 sha;
        sha.update(data);
        std::array<std::byte, 32> sha_hash;
        sha.finalize(sha_hash);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        double throughput = (data.size() / (1024.0 * 1024.0)) / (duration / 1000000.0);
        std::cout << "SHA-256 throughput: " << std::fixed << std::setprecision(2) 
                  << throughput << " MB/s (for comparison)" << std::endl;
    }
}

/**
 * @brief Benchmark small input performance
 */
void benchmark_small_inputs() {
    std::cout << "\nBenchmarking xxHash3 on small inputs..." << std::endl;
    
    std::vector<size_t> sizes = {4, 8, 16, 32, 64, 128};
    
    for (size_t size : sizes) {
        std::vector<std::byte> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<std::byte>(i);
        }
        
        const int iterations = 1000000;
        
        // 32-bit
        {
            auto start = std::chrono::high_resolution_clock::now();
            volatile uint32_t hash = 0;
            for (int i = 0; i < iterations; ++i) {
                hash ^= psyfer::hash::xxhash3_32::hash(data, i);
            }
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            
            std::cout << "Size " << std::setw(3) << size << " bytes - 32-bit: " 
                      << std::setw(5) << duration / iterations << " ns/hash";
        }
        
        // 64-bit
        {
            auto start = std::chrono::high_resolution_clock::now();
            volatile uint64_t hash = 0;
            for (int i = 0; i < iterations; ++i) {
                hash ^= psyfer::hash::xxhash3_64::hash(data, i);
            }
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            
            std::cout << " | 64-bit: " << std::setw(5) << duration / iterations << " ns/hash";
            
            // Calculate speedup
            double speedup = static_cast<double>(duration) / (duration / iterations);
            std::cout << std::endl;
        }
    }
}

/**
 * @brief Test xxHash3 24-bit variant (exotic size!)
 */
void test_xxhash3_24bit() {
    std::cout << "\nTesting xxHash3 24-bit variant..." << std::endl;
    
    // Test empty input
    {
        std::vector<std::byte> empty;
        uint32_t hash = psyfer::hash::xxhash3_24::hash(empty, 0);
        std::cout << "Empty hash (24-bit): " << std::hex << hash << std::dec 
                  << " (max: " << std::hex << 0xFFFFFF << std::dec << ")" << std::endl;
        assert(hash <= 0xFFFFFF);  // Must be within 24-bit range
    }
    
    // Test simple string
    {
        std::string test = "Hello, xxHash3-24!";
        uint32_t hash1 = psyfer::hash::xxhash3_24::hash(test, 0);
        uint32_t hash2 = psyfer::hash::xxhash3_24::hash(test, 0);
        std::cout << "String hash (24-bit): " << std::hex << hash1 << std::dec << std::endl;
        assert(hash1 == hash2);  // Deterministic
        assert(hash1 <= 0xFFFFFF);  // Within range
        
        // Different seed
        uint32_t hash3 = psyfer::hash::xxhash3_24::hash(test, 12345);
        std::cout << "With different seed: " << std::hex << hash3 << std::dec << std::endl;
        assert(hash3 <= 0xFFFFFF);  // Within range
        if (hash1 == hash3) {
            std::cout << "Warning: seed not affecting hash for size " << test.size() << std::endl;
        }
    }
    
    std::cout << "✓ 24-bit variant tests passed" << std::endl;
}

int main() {
    std::cout << "=== xxHash3 Tests ===" << std::endl;
    
    test_xxhash3_24bit();
    test_xxhash3_32bit();
    test_xxhash3_basic();
    test_xxhash3_streaming();
    test_xxhash3_128();
    test_xxhash3_sizes();
    test_xxhash3_quality();
    benchmark_xxhash3();
    benchmark_small_inputs();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}