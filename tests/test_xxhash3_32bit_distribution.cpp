/**
 * @file test_xxhash3_32bit_distribution.cpp
 * @brief Distribution tests specifically for xxHash3 32-bit variant
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
 * @brief Test bit distribution for 32-bit hash
 */
void test_32bit_distribution() {
    std::cout << "=== 32-bit Hash Bit Distribution Test ===" << std::endl;
    std::cout << "Testing if each bit position has roughly equal 0s and 1s...\n" << std::endl;
    
    const int num_samples = 100000;
    std::vector<int> bit_counts(32, 0);
    
    // Generate hashes from sequential inputs with a bit more entropy
    for (int i = 0; i < num_samples; ++i) {
        // Mix the input to avoid sequential patterns
        uint32_t input = i * 2654435761U;  // Large prime multiplier
        uint32_t hash = psyfer::hash::xxhash3_32::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&input), sizeof(input)), 0);
        
        // Count bits
        for (int bit = 0; bit < 32; ++bit) {
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
    
    for (int bit = 0; bit < 32; ++bit) {
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
    std::cout << (max_deviation < 3.0 ? "✓ PASS" : "✗ FAIL") << ": 32-bit distribution test" << std::endl;
}

/**
 * @brief Test avalanche effect for 32-bit hash
 */
void test_32bit_avalanche() {
    std::cout << "\n=== 32-bit Hash Avalanche Effect Test ===" << std::endl;
    std::cout << "Testing if small input changes cause large output changes...\n" << std::endl;
    
    const int num_tests = 10000;
    std::vector<double> bit_change_ratios;
    
    for (int test = 0; test < num_tests; ++test) {
        // Create random input
        std::vector<std::byte> input(64);
        for (size_t i = 0; i < input.size(); ++i) {
            input[i] = static_cast<std::byte>(rand() & 0xFF);
        }
        
        uint32_t hash1 = psyfer::hash::xxhash3_32::hash(input, 0);
        
        // Flip one random bit
        size_t byte_idx = rand() % input.size();
        int bit_idx = rand() % 8;
        input[byte_idx] ^= static_cast<std::byte>(1 << bit_idx);
        
        uint32_t hash2 = psyfer::hash::xxhash3_32::hash(input, 0);
        
        // Count bit differences
        uint32_t diff = hash1 ^ hash2;
        int changed_bits = __builtin_popcount(diff);
        bit_change_ratios.push_back(static_cast<double>(changed_bits) / 32.0);
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
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": 32-bit avalanche effect test" << std::endl;
}

/**
 * @brief Test collision resistance for 32-bit hash
 */
void test_32bit_collisions() {
    std::cout << "\n=== 32-bit Hash Collision Test ===" << std::endl;
    std::cout << "Testing for hash collisions (expecting some due to birthday paradox)...\n" << std::endl;
    
    // For 32-bit hash, expect first collision around 2^16 = 65536 hashes
    const int num_hashes = 100000;
    std::map<uint32_t, int> hash_map;
    int collisions = 0;
    
    for (int i = 0; i < num_hashes; ++i) {
        uint32_t hash = psyfer::hash::xxhash3_32::hash(
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
    
    // Expected collisions for 100k hashes with 32-bit output: ~1.16
    double expected = (static_cast<double>(num_hashes) * num_hashes) / (2.0 * 4294967296.0);
    std::cout << "Expected collisions (birthday paradox): ~" << expected << std::endl;
    
    // Allow reasonable range
    bool passed = collisions >= 0 && collisions <= 10;
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": Collision count is reasonable" << std::endl;
}

/**
 * @brief Test distribution across hash table buckets
 */
void test_32bit_bucket_distribution() {
    std::cout << "\n=== 32-bit Hash Table Distribution Test ===" << std::endl;
    std::cout << "Testing if hashes distribute evenly across buckets...\n" << std::endl;
    
    const int num_hashes = 1000000;
    const int num_buckets = 1024;  // Power of 2 for typical hash table
    std::vector<int> bucket_counts(num_buckets, 0);
    
    for (int i = 0; i < num_hashes; ++i) {
        uint32_t hash = psyfer::hash::xxhash3_32::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&i), sizeof(i)), 0);
        
        // Distribute to bucket (common hash table operation)
        int bucket = hash & (num_buckets - 1);  // Fast modulo for power of 2
        bucket_counts[bucket]++;
    }
    
    // Calculate statistics
    int expected = num_hashes / num_buckets;
    int min_count = *std::min_element(bucket_counts.begin(), bucket_counts.end());
    int max_count = *std::max_element(bucket_counts.begin(), bucket_counts.end());
    
    double chi_sq = chi_square_test(bucket_counts, expected);
    
    std::cout << "Expected count per bucket: " << expected << std::endl;
    std::cout << "Min count: " << min_count << std::endl;
    std::cout << "Max count: " << max_count << std::endl;
    std::cout << "Chi-square statistic: " << chi_sq << std::endl;
    
    // For 1023 degrees of freedom at 0.05 significance, critical value is ~1118
    bool passed = chi_sq < 1118;
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": Bucket distribution test" << std::endl;
}

/**
 * @brief Test performance-critical small string hashing
 */
void test_32bit_small_strings() {
    std::cout << "\n=== 32-bit Small String Hash Test ===" << std::endl;
    std::cout << "Testing hash quality for small strings (common use case)...\n" << std::endl;
    
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
        uint32_t hash = psyfer::hash::xxhash3_32::hash(str, 0);
        hashes.insert(hash);
    }
    
    std::cout << "Unique hashes: " << hashes.size() << "/" << patterns.size() << std::endl;
    bool no_collisions = hashes.size() == patterns.size();
    std::cout << (no_collisions ? "✓ PASS" : "✗ FAIL") << ": No collisions in small strings" << std::endl;
    
    // Test similar strings produce different hashes
    uint32_t hash_a = psyfer::hash::xxhash3_32::hash("test", 0);
    uint32_t hash_b = psyfer::hash::xxhash3_32::hash("Test", 0);
    uint32_t hash_c = psyfer::hash::xxhash3_32::hash("tset", 0);
    
    int bits_diff_ab = __builtin_popcount(hash_a ^ hash_b);
    int bits_diff_ac = __builtin_popcount(hash_a ^ hash_c);
    
    std::cout << "Bits different 'test' vs 'Test': " << bits_diff_ab << "/32" << std::endl;
    std::cout << "Bits different 'test' vs 'tset': " << bits_diff_ac << "/32" << std::endl;
    
    bool good_diffusion = bits_diff_ab >= 10 && bits_diff_ac >= 10;
    std::cout << (good_diffusion ? "✓ PASS" : "✗ FAIL") << ": Good diffusion for similar strings" << std::endl;
}

/**
 * @brief Test seed sensitivity
 */
void test_32bit_seed_sensitivity() {
    std::cout << "\n=== 32-bit Seed Sensitivity Test ===" << std::endl;
    std::cout << "Testing if seed parameter properly affects output...\n" << std::endl;
    
    std::string test_data = "This is a test string for seed sensitivity";
    
    // Test multiple seeds
    std::vector<uint64_t> seeds = {0, 1, 42, 12345, 0xDEADBEEF, 0xCAFEBABE};
    std::set<uint32_t> hashes;
    
    for (uint64_t seed : seeds) {
        uint32_t hash = psyfer::hash::xxhash3_32::hash(test_data, seed);
        hashes.insert(hash);
        std::cout << "Seed " << std::setw(10) << seed << " -> hash: " 
                  << std::hex << hash << std::dec << std::endl;
    }
    
    bool all_different = hashes.size() == seeds.size();
    std::cout << "\nUnique hashes: " << hashes.size() << "/" << seeds.size() << std::endl;
    std::cout << (all_different ? "✓ PASS" : "✗ FAIL") << ": All seeds produce different hashes" << std::endl;
}

int main() {
    std::cout << "=== xxHash3 32-bit Distribution Tests ===" << std::endl;
    std::cout << "Testing the quality of 32-bit hash distribution...\n" << std::endl;
    
    // Seed random for reproducibility
    srand(42);
    
    test_32bit_distribution();
    test_32bit_avalanche();
    test_32bit_collisions();
    test_32bit_bucket_distribution();
    test_32bit_small_strings();
    test_32bit_seed_sensitivity();
    
    std::cout << "\n=== All 32-bit distribution tests completed ===" << std::endl;
    return 0;
}