/**
 * @file test_xxhash3_distribution.cpp
 * @brief Comprehensive distribution tests for xxHash3
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
 * @brief Test bit distribution
 */
void test_bit_distribution() {
    std::cout << "=== Bit Distribution Test ===" << std::endl;
    std::cout << "Testing if each bit position has roughly equal 0s and 1s...\n" << std::endl;
    
    const int num_samples = 100000;
    std::vector<int> bit_counts(64, 0);
    
    // Generate hashes from sequential inputs
    for (int i = 0; i < num_samples; ++i) {
        uint64_t hash = psyfer::hash::xxhash3_64::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&i), sizeof(i)), 0);
        
        // Count bits
        for (int bit = 0; bit < 64; ++bit) {
            if (hash & (1ULL << bit)) {
                bit_counts[bit]++;
            }
        }
    }
    
    // Analyze results
    std::cout << "Bit position : 1s count : Deviation from 50%" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    
    double max_deviation = 0.0;
    int worst_bit = -1;
    
    for (int bit = 0; bit < 64; ++bit) {
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
    std::cout << (max_deviation < 3.0 ? "✓ PASS" : "✗ FAIL") << ": Bit distribution test" << std::endl;
}

/**
 * @brief Test byte distribution
 */
void test_byte_distribution() {
    std::cout << "\n=== Byte Distribution Test ===" << std::endl;
    std::cout << "Testing if each byte value appears with equal frequency...\n" << std::endl;
    
    const int num_samples = 1000000;
    std::vector<std::vector<int>> byte_counts(8, std::vector<int>(256, 0));
    
    // Generate hashes
    for (int i = 0; i < num_samples; ++i) {
        uint64_t hash = psyfer::hash::xxhash3_64::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&i), sizeof(i)), 0);
        
        // Count byte values
        for (int byte_pos = 0; byte_pos < 8; ++byte_pos) {
            uint8_t byte_val = (hash >> (byte_pos * 8)) & 0xFF;
            byte_counts[byte_pos][byte_val]++;
        }
    }
    
    // Chi-square test for each byte position
    int expected = num_samples / 256;
    std::cout << "Byte Position : Chi-Square : Status" << std::endl;
    std::cout << "-----------------------------------" << std::endl;
    
    for (int byte_pos = 0; byte_pos < 8; ++byte_pos) {
        double chi_sq = chi_square_test(byte_counts[byte_pos], expected);
        // Critical value for 255 degrees of freedom at 0.05 significance is ~293
        bool passed = chi_sq < 293;
        
        std::cout << std::setw(13) << byte_pos << " : "
                  << std::setw(10) << std::fixed << std::setprecision(2) << chi_sq
                  << " : " << (passed ? "PASS" : "FAIL") << std::endl;
    }
}

/**
 * @brief Test avalanche effect
 */
void test_avalanche_effect() {
    std::cout << "\n=== Avalanche Effect Test ===" << std::endl;
    std::cout << "Testing if small input changes cause large output changes...\n" << std::endl;
    
    const int num_tests = 10000;
    std::vector<double> bit_change_ratios;
    
    for (int test = 0; test < num_tests; ++test) {
        // Create random input
        std::vector<std::byte> input(64);
        for (size_t i = 0; i < input.size(); ++i) {
            input[i] = static_cast<std::byte>(rand() & 0xFF);
        }
        
        uint64_t hash1 = psyfer::hash::xxhash3_64::hash(input, 0);
        
        // Flip one random bit
        size_t byte_idx = rand() % input.size();
        int bit_idx = rand() % 8;
        input[byte_idx] ^= static_cast<std::byte>(1 << bit_idx);
        
        uint64_t hash2 = psyfer::hash::xxhash3_64::hash(input, 0);
        
        // Count bit differences
        uint64_t diff = hash1 ^ hash2;
        int changed_bits = __builtin_popcountll(diff);
        bit_change_ratios.push_back(static_cast<double>(changed_bits) / 64.0);
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
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": Avalanche effect test" << std::endl;
}

/**
 * @brief Test collision resistance (birthday paradox)
 */
void test_collision_resistance() {
    std::cout << "\n=== Collision Resistance Test ===" << std::endl;
    std::cout << "Testing for hash collisions using birthday paradox...\n" << std::endl;
    
    // For a 64-bit hash, we expect first collision around 2^32 hashes
    // We'll test with much fewer and ensure no collisions
    const int num_hashes = 1000000;
    std::map<uint64_t, int> hash_map;
    int collisions = 0;
    
    for (int i = 0; i < num_hashes; ++i) {
        // Generate hash from counter
        uint64_t hash = psyfer::hash::xxhash3_64::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&i), sizeof(i)), 0);
        
        if (hash_map.find(hash) != hash_map.end()) {
            collisions++;
            std::cout << "Collision found: input " << i << " and " << hash_map[hash] 
                      << " both hash to " << std::hex << hash << std::dec << std::endl;
        } else {
            hash_map[hash] = i;
        }
    }
    
    std::cout << "Total collisions in " << num_hashes << " hashes: " << collisions << std::endl;
    std::cout << (collisions == 0 ? "✓ PASS" : "✗ FAIL") << ": No collisions found" << std::endl;
}

/**
 * @brief Test correlation between consecutive hashes
 */
void test_consecutive_correlation() {
    std::cout << "\n=== Consecutive Hash Correlation Test ===" << std::endl;
    std::cout << "Testing if consecutive inputs produce uncorrelated hashes...\n" << std::endl;
    
    const int num_tests = 100000;
    std::vector<int> hamming_distances;
    
    for (int i = 0; i < num_tests; ++i) {
        uint64_t hash1 = psyfer::hash::xxhash3_64::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&i), sizeof(i)), 0);
        
        int next = i + 1;
        uint64_t hash2 = psyfer::hash::xxhash3_64::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&next), sizeof(next)), 0);
        
        // Calculate Hamming distance
        uint64_t diff = hash1 ^ hash2;
        int distance = __builtin_popcountll(diff);
        hamming_distances.push_back(distance);
    }
    
    // Calculate average Hamming distance
    double avg_distance = std::accumulate(hamming_distances.begin(), hamming_distances.end(), 0.0) / num_tests;
    
    // Build histogram
    std::vector<int> histogram(65, 0);
    for (int dist : hamming_distances) {
        histogram[dist]++;
    }
    
    std::cout << "Average Hamming distance: " << avg_distance << " (ideal: 32)" << std::endl;
    std::cout << "\nDistance distribution (showing top values):" << std::endl;
    
    for (int i = 20; i <= 44; ++i) {
        if (histogram[i] > 0) {
            std::cout << std::setw(2) << i << ": ";
            int bar_length = histogram[i] * 50 / num_tests;
            for (int j = 0; j < bar_length; ++j) std::cout << "█";
            std::cout << " " << histogram[i] << std::endl;
        }
    }
    
    bool passed = std::abs(avg_distance - 32) < 2;
    std::cout << "\n" << (passed ? "✓ PASS" : "✗ FAIL") << ": Consecutive hash correlation test" << std::endl;
}

/**
 * @brief Test hash distribution across buckets
 */
void test_bucket_distribution() {
    std::cout << "\n=== Bucket Distribution Test ===" << std::endl;
    std::cout << "Testing if hashes distribute evenly across buckets...\n" << std::endl;
    
    const int num_hashes = 1000000;
    const int num_buckets = 1000;
    std::vector<int> bucket_counts(num_buckets, 0);
    
    for (int i = 0; i < num_hashes; ++i) {
        uint64_t hash = psyfer::hash::xxhash3_64::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(&i), sizeof(i)), 0);
        
        // Distribute to bucket
        int bucket = hash % num_buckets;
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
    
    // For 999 degrees of freedom at 0.05 significance, critical value is ~1074
    bool passed = chi_sq < 1074;
    std::cout << (passed ? "✓ PASS" : "✗ FAIL") << ": Bucket distribution test" << std::endl;
}

/**
 * @brief Test with different input patterns
 */
void test_input_patterns() {
    std::cout << "\n=== Input Pattern Test ===" << std::endl;
    std::cout << "Testing hash quality with various input patterns...\n" << std::endl;
    
    struct Pattern {
        std::string name;
        std::function<std::vector<std::byte>(int)> generator;
    };
    
    std::vector<Pattern> patterns = {
        {"Sequential", [](int i) {
            std::vector<std::byte> data(8);
            *reinterpret_cast<uint64_t*>(data.data()) = i;
            return data;
        }},
        {"All zeros with counter", [](int i) {
            std::vector<std::byte> data(64, std::byte{0});
            *reinterpret_cast<int*>(data.data()) = i;
            return data;
        }},
        {"All ones with counter", [](int i) {
            std::vector<std::byte> data(64, std::byte{0xFF});
            *reinterpret_cast<int*>(data.data()) = i;
            return data;
        }},
        {"Alternating pattern", [](int i) {
            std::vector<std::byte> data(64);
            for (size_t j = 0; j < data.size(); ++j) {
                data[j] = static_cast<std::byte>((j % 2) ? 0xAA : 0x55);
            }
            *reinterpret_cast<int*>(data.data()) = i;
            return data;
        }},
        {"Single bit set", [](int i) {
            std::vector<std::byte> data(64, std::byte{0});
            int byte_idx = (i / 8) % 64;
            int bit_idx = i % 8;
            data[byte_idx] = static_cast<std::byte>(1 << bit_idx);
            return data;
        }}
    };
    
    for (const auto& pattern : patterns) {
        std::cout << "\nTesting pattern: " << pattern.name << std::endl;
        
        // Generate hashes and check distribution
        const int num_samples = 10000;
        std::set<uint64_t> unique_hashes;
        std::vector<int> bit_counts(64, 0);
        
        for (int i = 0; i < num_samples; ++i) {
            auto data = pattern.generator(i);
            uint64_t hash = psyfer::hash::xxhash3_64::hash(data, 0);
            unique_hashes.insert(hash);
            
            // Count bits
            for (int bit = 0; bit < 64; ++bit) {
                if (hash & (1ULL << bit)) {
                    bit_counts[bit]++;
                }
            }
        }
        
        // Check uniqueness
        std::cout << "  Unique hashes: " << unique_hashes.size() << "/" << num_samples;
        bool unique_ok = unique_hashes.size() == num_samples;
        std::cout << (unique_ok ? " ✓" : " ✗") << std::endl;
        
        // Check bit distribution
        double max_deviation = 0.0;
        for (int bit = 0; bit < 64; ++bit) {
            double ratio = static_cast<double>(bit_counts[bit]) / num_samples;
            double deviation = std::abs(ratio - 0.5);
            max_deviation = std::max(max_deviation, deviation);
        }
        
        std::cout << "  Max bit deviation: " << (max_deviation * 100) << "%";
        bool dist_ok = max_deviation < 0.1;  // 10% threshold
        std::cout << (dist_ok ? " ✓" : " ✗") << std::endl;
    }
}

int main() {
    std::cout << "=== xxHash3 Distribution Tests ===" << std::endl;
    std::cout << "Testing the quality of hash distribution...\n" << std::endl;
    
    // Seed random for reproducibility
    srand(42);
    
    test_bit_distribution();
    test_byte_distribution();
    test_avalanche_effect();
    test_collision_resistance();
    test_consecutive_correlation();
    test_bucket_distribution();
    test_input_patterns();
    
    std::cout << "\n=== All distribution tests completed ===" << std::endl;
    return 0;
}