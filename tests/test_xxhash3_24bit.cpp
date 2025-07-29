/**
 * @file test_xxhash3_24bit.cpp
 * @brief Tests for xxHash3 24-bit variant
 */

#include <psyfer.hpp>
#include <psyfer/hash/xxhash3.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <set>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <bitset>
#include <functional>
#include <cstdlib>

/**
 * @brief Chi-square test for uniform distribution
 */
double chi_square_test(const std::vector<int>& observed, int expected) {
    double chi_square = 0.0;
    for (int count : observed) {
        double diff = count - expected;
        chi_square += (diff * diff) / expected;
    }
    return chi_square;
}

/**
 * @brief Test bit distribution for 24-bit hash
 */
void test_24bit_distribution() {
    std::cout << "=== 24-bit Hash Bit Distribution Test ===" << std::endl;
    std::cout << "Testing if each bit position has roughly equal 0s and 1s...\n" << std::endl;
    
    const int num_samples = 100000;
    std::vector<int> bit_counts(24, 0);
    
    // Generate hashes from sequential inputs with entropy
    for (int i = 0; i < num_samples; ++i) {
        // Mix the input to avoid sequential patterns
        uint32_t input = i * 2654435761U;  // Large prime multiplier
        uint32_t hash = psyfer::hash::xxhash3_24::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&input), sizeof(input)), 0);
        
        // Verify it's actually 24-bit
        if (hash > 0xFFFFFF) {
            std::cout << "ERROR: Hash exceeds 24 bits: " << std::hex << hash << std::dec << std::endl;
        }
        
        // Count bits
        for (int bit = 0; bit < 24; ++bit) {
            if (hash & (1U << bit)) {
                bit_counts[bit]++;
            }
        }
    }
    
    // Analyze results
    std::cout << "Bit position : 1s count : Deviation from 50%" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    
    double max_deviation = 0.0;
    int worst_bit = -1;
    
    for (int bit = 0; bit < 24; ++bit) {
        double ratio = static_cast<double>(bit_counts[bit]) / num_samples;
        double deviation = std::abs(ratio - 0.5) * 100;
        
        if (deviation > max_deviation) {
            max_deviation = deviation;
            worst_bit = bit;
        }
        
        std::cout << std::setw(12) << bit << " : " 
                  << std::setw(8) << bit_counts[bit] << " : "
                  << std::fixed << std::setprecision(2) << deviation << "%";
        
        if (deviation > 2.0) {
            std::cout << " ⚠️";
        }
        std::cout << std::endl;
    }
    
    std::cout << "\nWorst bit: " << worst_bit << " with " << max_deviation << "% deviation" << std::endl;
    std::cout << (max_deviation < 3.0 ? "✓ PASS" : "✗ FAIL") << ": 24-bit distribution test" << std::endl;
}

/**
 * @brief Test avalanche effect for 24-bit hash
 */
void test_24bit_avalanche() {
    std::cout << "\n=== 24-bit Hash Avalanche Effect Test ===" << std::endl;
    std::cout << "Testing if small input changes cause large output changes...\n" << std::endl;
    
    const int num_tests = 10000;
    std::vector<double> bit_change_ratios;
    
    for (int test = 0; test < num_tests; ++test) {
        // Create random input
        std::vector<std::byte> input(64);
        for (size_t i = 0; i < input.size(); ++i) {
            input[i] = static_cast<std::byte>(rand() & 0xFF);
        }
        
        uint32_t hash1 = psyfer::hash::xxhash3_24::hash(input, 0);
        
        // Flip one random bit
        size_t byte_idx = rand() % input.size();
        int bit_idx = rand() % 8;
        input[byte_idx] ^= static_cast<std::byte>(1 << bit_idx);
        
        uint32_t hash2 = psyfer::hash::xxhash3_24::hash(input, 0);
        
        // Count bit differences
        uint32_t diff = hash1 ^ hash2;
        int changed_bits = __builtin_popcount(diff & 0xFFFFFF);  // Mask to 24 bits
        bit_change_ratios.push_back(static_cast<double>(changed_bits) / 24.0);
    }
    
    // Calculate statistics
    double mean = std::accumulate(bit_change_ratios.begin(), bit_change_ratios.end(), 0.0) / num_tests;
    double variance = 0.0;
    for (double ratio : bit_change_ratios) {
        variance += (ratio - mean) * (ratio - mean);
    }
    variance /= num_tests;
    double std_dev = std::sqrt(variance);
    
    std::cout << "Mean bit change ratio: " << mean << " (ideal: 0.5)" << std::endl;
    std::cout << "Standard deviation: " << std_dev << std::endl;
    
    // Good avalanche: mean should be close to 0.5
    bool passed = std::abs(mean - 0.5) < 0.05;
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": 24-bit avalanche effect test" << std::endl;
}

/**
 * @brief Test collision resistance for 24-bit hash
 */
void test_24bit_collisions() {
    std::cout << "\n=== 24-bit Hash Collision Test ===" << std::endl;
    std::cout << "Testing for hash collisions (expecting some due to birthday paradox)...\n" << std::endl;
    
    // For 24-bit hash, expect first collision around 2^12 = 4096 hashes
    const int num_hashes = 10000;
    std::map<uint32_t, int> hash_map;
    int collisions = 0;
    
    for (int i = 0; i < num_hashes; ++i) {
        uint32_t hash = psyfer::hash::xxhash3_24::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&i), sizeof(i)), 0);
        
        if (hash_map.find(hash) != hash_map.end()) {
            collisions++;
            if (collisions <= 5) {  // Show first few collisions
                std::cout << "Collision found: input " << i << " and " << hash_map[hash] 
                          << " both hash to " << std::hex << hash << std::dec << std::endl;
            }
        } else {
            hash_map[hash] = i;
        }
    }
    
    std::cout << "Total collisions in " << num_hashes << " hashes: " << collisions << std::endl;
    
    // Expected collisions for 10k hashes with 24-bit output
    double expected = (static_cast<double>(num_hashes) * num_hashes) / (2.0 * 16777216.0);
    std::cout << "Expected collisions (birthday paradox): ~" << expected << std::endl;
    
    // Allow reasonable range
    bool passed = collisions >= 0 && collisions <= 10;
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": Collision count is reasonable" << std::endl;
}

/**
 * @brief Test small string performance
 */
void test_24bit_small_strings() {
    std::cout << "\n=== 24-bit Small String Hash Test ===" << std::endl;
    std::cout << "Testing hash quality for small strings...\n" << std::endl;
    
    // Common small string patterns
    std::vector<std::string> patterns = {
        "a", "b", "c", "aa", "ab", "ba", "aaa", "aab", "aba", "baa",
        "test", "Test", "TEST", "test1", "test2", "1test", "2test",
        "key", "Key", "KEY", "key1", "key2", "1key", "2key",
        "id", "ID", "Id", "id1", "id2", "1id", "2id"
    };
    
    std::set<uint32_t> hashes;
    std::cout << "Testing " << patterns.size() << " small string patterns..." << std::endl;
    
    for (const auto& str : patterns) {
        uint32_t hash = psyfer::hash::xxhash3_24::hash(str, 0);
        hashes.insert(hash);
    }
    
    std::cout << "Unique hashes: " << hashes.size() << "/" << patterns.size() << std::endl;
    bool no_collisions = hashes.size() == patterns.size();
    std::cout << (no_collisions ? "✓ PASS" : "✗ FAIL") << ": No collisions in small strings" << std::endl;
}

/**
 * @brief Test hash value range
 */
void test_24bit_range() {
    std::cout << "\n=== 24-bit Hash Range Test ===" << std::endl;
    std::cout << "Testing if hash values stay within 24-bit range...\n" << std::endl;
    
    const int num_tests = 100000;
    uint32_t max_hash = 0;
    uint32_t min_hash = 0xFFFFFF;
    
    for (int i = 0; i < num_tests; ++i) {
        // Generate random data
        std::vector<std::byte> data(rand() % 256 + 1);
        for (auto& byte : data) {
            byte = static_cast<std::byte>(rand() & 0xFF);
        }
        
        uint32_t hash = psyfer::hash::xxhash3_24::hash(data, rand());
        
        if (hash > 0xFFFFFF) {
            std::cout << "ERROR: Hash exceeds 24 bits: " << std::hex << hash << std::dec << std::endl;
        }
        
        max_hash = std::max(max_hash, hash);
        min_hash = std::min(min_hash, hash);
    }
    
    std::cout << "Min hash: " << std::hex << min_hash << std::dec << std::endl;
    std::cout << "Max hash: " << std::hex << max_hash << std::dec << std::endl;
    
    bool passed = max_hash <= 0xFFFFFF;
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": All hashes within 24-bit range" << std::endl;
    
    // Check if we're using the full range
    bool good_range = max_hash > 0xF00000 && min_hash < 0x0FFFFF;
    std::cout << (good_range ? "✓ PASS" : "✗ FAIL") << ": Good use of 24-bit range" << std::endl;
}

/**
 * @brief Benchmark 24-bit performance
 */
void benchmark_24bit() {
    std::cout << "\n=== 24-bit Hash Performance Test ===" << std::endl;
    std::cout << "Comparing performance across different hash sizes...\n" << std::endl;
    
    std::vector<size_t> sizes = {4, 8, 16, 32, 64, 128, 256};
    
    for (size_t size : sizes) {
        std::vector<std::byte> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<std::byte>(i);
        }
        
        const int iterations = 1000000;
        
        // 24-bit
        auto start = std::chrono::high_resolution_clock::now();
        volatile uint32_t hash = 0;
        for (int i = 0; i < iterations; ++i) {
            hash ^= psyfer::hash::xxhash3_24::hash(data, i);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration_24 = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        
        // 32-bit for comparison
        start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            hash ^= psyfer::hash::xxhash3_32::hash(data, i);
        }
        end = std::chrono::high_resolution_clock::now();
        auto duration_32 = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        
        std::cout << "Size " << std::setw(3) << size << " bytes: "
                  << "24-bit: " << std::setw(5) << duration_24 / iterations << " ns/hash | "
                  << "32-bit: " << std::setw(5) << duration_32 / iterations << " ns/hash | "
                  << "Speedup: " << std::fixed << std::setprecision(2) 
                  << (static_cast<double>(duration_32) / duration_24) << "x" << std::endl;
    }
}

int main() {
    std::cout << "=== xxHash3 24-bit Tests ===" << std::endl;
    std::cout << "Testing the exotic 24-bit variant...\n" << std::endl;
    
    // Seed random for reproducibility
    srand(42);
    
    test_24bit_distribution();
    test_24bit_avalanche();
    test_24bit_collisions();
    test_24bit_small_strings();
    test_24bit_range();
    benchmark_24bit();
    
    std::cout << "\n=== All 24-bit tests completed ===" << std::endl;
    return 0;
}