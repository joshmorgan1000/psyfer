/**
 * @file test_hmac_comprehensive.cpp
 * @brief Comprehensive test suite for HMAC-SHA256 and HMAC-SHA512
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cstring>

// Test vectors from RFC 4231
struct HMACTestVector {
    std::string name;
    std::vector<uint8_t> key;
    std::string data;
    std::string hmac_sha256_expected;
    std::string hmac_sha512_expected;
};

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

void print_hex(const std::string& label, std::span<const std::byte> data) {
    std::cout << label << ": ";
    for (auto b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(static_cast<unsigned char>(b));
    }
    std::cout << std::dec << "\n";
}

bool test_hmac_sha256() {
    std::cout << "\n=== HMAC-SHA256 Tests ===\n";
    
    // RFC 4231 Test Vectors
    std::vector<HMACTestVector> vectors = {
        {
            "Test Case 1",
            std::vector<uint8_t>(20, 0x0b),  // 20 bytes of 0x0b
            "Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        },
        {
            "Test Case 2",
            {0x4a, 0x65, 0x66, 0x65},  // "Jefe"
            "what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        },
        {
            "Test Case 3",
            std::vector<uint8_t>(20, 0xaa),  // 20 bytes of 0xaa
            std::string(50, 0xdd),  // 50 bytes of 0xdd
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        },
        {
            "Test Case 4",
            hex_to_bytes("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            std::string(50, 0xcd),  // 50 bytes of 0xcd
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
        },
        {
            "Test Case 6 - Large key",
            std::vector<uint8_t>(131, 0xaa),  // 131 bytes of 0xaa
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        },
        {
            "Test Case 7 - Large key and data",
            std::vector<uint8_t>(131, 0xaa),  // 131 bytes of 0xaa
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
        }
    };
    
    bool all_pass = true;
    
    for (const auto& tv : vectors) {
        std::cout << "\n" << tv.name << ":\n";
        std::cout << "Key size: " << tv.key.size() << " bytes\n";
        std::cout << "Data size: " << tv.data.size() << " bytes\n";
        
        // Convert key and data
        std::vector<std::byte> key_bytes(tv.key.size());
        std::memcpy(key_bytes.data(), tv.key.data(), tv.key.size());
        
        std::vector<std::byte> data_bytes(tv.data.size());
        std::memcpy(data_bytes.data(), tv.data.data(), tv.data.size());
        
        // Test HMAC-SHA256
        std::array<std::byte, 32> hmac256_output;
        psyfer::hash::hmac_sha256::hmac(key_bytes, data_bytes, hmac256_output);
        
        // Convert expected to bytes for comparison
        auto expected_bytes = hex_to_bytes(tv.hmac_sha256_expected);
        
        bool pass = true;
        for (size_t i = 0; i < 32; ++i) {
            if (static_cast<uint8_t>(hmac256_output[i]) != expected_bytes[i]) {
                pass = false;
                break;
            }
        }
        
        print_hex("Computed", hmac256_output);
        std::cout << "Expected: " << tv.hmac_sha256_expected << "\n";
        std::cout << "Result: " << (pass ? "PASS" : "FAIL") << "\n";
        
        if (!pass) all_pass = false;
    }
    
    return all_pass;
}

bool test_hmac_sha512() {
    std::cout << "\n=== HMAC-SHA512 Tests ===\n";
    
    // Same test vectors as SHA256, but checking SHA512 results
    std::vector<HMACTestVector> vectors = {
        {
            "Test Case 1",
            std::vector<uint8_t>(20, 0x0b),
            "Hi There",
            "",  // SHA256 not used here
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        },
        {
            "Test Case 2",
            {0x4a, 0x65, 0x66, 0x65},  // "Jefe"
            "what do ya want for nothing?",
            "",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        }
    };
    
    bool all_pass = true;
    
    for (const auto& tv : vectors) {
        if (tv.hmac_sha512_expected.empty()) continue;
        
        std::cout << "\n" << tv.name << ":\n";
        
        // Convert key and data
        std::vector<std::byte> key_bytes(tv.key.size());
        std::memcpy(key_bytes.data(), tv.key.data(), tv.key.size());
        
        std::vector<std::byte> data_bytes(tv.data.size());
        std::memcpy(data_bytes.data(), tv.data.data(), tv.data.size());
        
        // Test HMAC-SHA512
        std::array<std::byte, 64> hmac512_output;
        psyfer::hash::hmac_sha512::hmac(key_bytes, data_bytes, hmac512_output);
        
        // Convert expected to bytes for comparison
        auto expected_bytes = hex_to_bytes(tv.hmac_sha512_expected);
        
        bool pass = true;
        for (size_t i = 0; i < 64; ++i) {
            if (static_cast<uint8_t>(hmac512_output[i]) != expected_bytes[i]) {
                pass = false;
                break;
            }
        }
        
        print_hex("Computed", hmac512_output);
        std::cout << "Expected: " << tv.hmac_sha512_expected << "\n";
        std::cout << "Result: " << (pass ? "PASS" : "FAIL") << "\n";
        
        if (!pass) all_pass = false;
    }
    
    return all_pass;
}

void test_hmac_incremental() {
    std::cout << "\n=== HMAC Incremental Update Tests ===\n";
    
    // Test incremental updates produce same result as one-shot
    std::vector<std::byte> key(32);
    psyfer::utils::secure_random::generate(key);
    
    std::string test_data = "The quick brown fox jumps over the lazy dog. ";
    test_data += test_data; // Make it longer
    
    std::vector<std::byte> data(test_data.size());
    std::memcpy(data.data(), test_data.data(), test_data.size());
    
    // One-shot HMAC-SHA256
    std::array<std::byte, 32> oneshot_result;
    psyfer::hash::hmac_sha256::hmac(key, data, oneshot_result);
    
    // Incremental HMAC-SHA256
    psyfer::hash::hmac_sha256 hmac(key);
    hmac.update(std::span<const std::byte>(data.data(), data.size() / 2));
    hmac.update(std::span<const std::byte>(data.data() + data.size() / 2, data.size() - data.size() / 2));
    
    std::array<std::byte, 32> incremental_result;
    hmac.finalize(incremental_result);
    
    bool match = std::memcmp(oneshot_result.data(), incremental_result.data(), 32) == 0;
    
    std::cout << "One-shot vs Incremental: " << (match ? "MATCH" : "MISMATCH") << "\n";
    print_hex("One-shot", oneshot_result);
    print_hex("Incremental", incremental_result);
}

void test_hmac_edge_cases() {
    std::cout << "\n=== HMAC Edge Cases ===\n";
    
    // Empty key (should still work)
    std::vector<std::byte> empty_key;
    std::vector<std::byte> data(16);
    psyfer::utils::secure_random::generate(data);
    
    std::array<std::byte, 32> result1;
    psyfer::hash::hmac_sha256::hmac(empty_key, data, result1);
    std::cout << "Empty key test: ";
    print_hex("Result", result1);
    
    // Empty data
    std::vector<std::byte> key(32);
    psyfer::utils::secure_random::generate(key);
    std::vector<std::byte> empty_data;
    
    std::array<std::byte, 32> result2;
    psyfer::hash::hmac_sha256::hmac(key, empty_data, result2);
    std::cout << "\nEmpty data test: ";
    print_hex("Result", result2);
    
    // Very large key (> block size)
    std::vector<std::byte> large_key(256);
    psyfer::utils::secure_random::generate(large_key);
    
    std::array<std::byte, 32> result3;
    psyfer::hash::hmac_sha256::hmac(large_key, data, result3);
    std::cout << "\nLarge key test (256 bytes): ";
    print_hex("Result", result3);
}


void test_hmac_security_properties() {
    std::cout << "\n=== HMAC Security Properties ===\n";
    
    // Test that changing one bit of key changes output significantly
    std::vector<std::byte> key1(32);
    psyfer::utils::secure_random::generate(key1);
    
    std::vector<std::byte> key2 = key1;
    key2[0] = static_cast<std::byte>(static_cast<uint8_t>(key2[0]) ^ 0x01);  // Flip one bit
    
    std::string test_data = "Test message for HMAC";
    std::vector<std::byte> data(test_data.size());
    std::memcpy(data.data(), test_data.data(), test_data.size());
    
    std::array<std::byte, 32> result1, result2;
    psyfer::hash::hmac_sha256::hmac(key1, data, result1);
    psyfer::hash::hmac_sha256::hmac(key2, data, result2);
    
    // Count different bits
    int different_bits = 0;
    for (size_t i = 0; i < 32; ++i) {
        uint8_t xor_result = static_cast<uint8_t>(result1[i]) ^ static_cast<uint8_t>(result2[i]);
        for (int bit = 0; bit < 8; ++bit) {
            if (xor_result & (1 << bit)) different_bits++;
        }
    }
    
    std::cout << "Key difference: 1 bit\n";
    std::cout << "Output difference: " << different_bits << " bits (out of 256)\n";
    std::cout << "Avalanche effect: " << (different_bits * 100.0 / 256.0) << "%\n";
    
    // Test that changing one bit of data changes output significantly
    std::vector<std::byte> data2 = data;
    data2[0] = static_cast<std::byte>(static_cast<uint8_t>(data2[0]) ^ 0x01);
    
    std::array<std::byte, 32> result3;
    psyfer::hash::hmac_sha256::hmac(key1, data2, result3);
    
    different_bits = 0;
    for (size_t i = 0; i < 32; ++i) {
        uint8_t xor_result = static_cast<uint8_t>(result1[i]) ^ static_cast<uint8_t>(result3[i]);
        for (int bit = 0; bit < 8; ++bit) {
            if (xor_result & (1 << bit)) different_bits++;
        }
    }
    
    std::cout << "\nData difference: 1 bit\n";
    std::cout << "Output difference: " << different_bits << " bits (out of 256)\n";
    std::cout << "Avalanche effect: " << (different_bits * 100.0 / 256.0) << "%\n";
}

void compare_hardware_vs_software() {
    std::cout << "\n=== Hardware vs Software Performance Comparison ===\n";
    
    const size_t iterations = 10000;
    const size_t data_size = 1024;
    
    std::vector<std::byte> key(32);
    psyfer::utils::secure_random::generate(key);
    
    std::vector<std::byte> data(data_size);
    psyfer::utils::secure_random::generate(data);
    
    std::array<std::byte, 32> result;
    
    // Test with hardware acceleration (if available)
    psyfer::config::disable_software_only();
    
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        psyfer::hash::hmac_sha256::hmac(key, data, result);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto hw_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Hardware-accelerated HMAC-SHA256:\n";
    std::cout << "  " << iterations << " iterations in " << hw_duration.count() << " µs\n";
    std::cout << "  " << (iterations * 1000000.0) / hw_duration.count() << " ops/sec\n";
    
    // Save hardware result for comparison
    std::array<std::byte, 32> hw_result = result;
    
    // Test with software only
    psyfer::config::enable_software_only();
    
    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        psyfer::hash::hmac_sha256::hmac(key, data, result);
    }
    end = std::chrono::high_resolution_clock::now();
    auto sw_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "\nSoftware-only HMAC-SHA256:\n";
    std::cout << "  " << iterations << " iterations in " << sw_duration.count() << " µs\n";
    std::cout << "  " << (iterations * 1000000.0) / sw_duration.count() << " ops/sec\n";
    
    // Compare results
    bool results_match = std::memcmp(hw_result.data(), result.data(), 32) == 0;
    std::cout << "\nResults match: " << (results_match ? "YES" : "NO") << "\n";
    
    if (hw_duration < sw_duration) {
        double speedup = static_cast<double>(sw_duration.count()) / hw_duration.count();
        std::cout << "Hardware acceleration speedup: " << speedup << "x\n";
    }
    
    // Reset to default
    psyfer::config::disable_software_only();
}

int main() {
    std::cout << "=== HMAC Comprehensive Test Suite ===\n";
    std::cout << "Testing HMAC-SHA256 and HMAC-SHA512 implementations\n";
    
    bool all_pass = true;
    
    // Run all tests
    all_pass &= test_hmac_sha256();
    all_pass &= test_hmac_sha512();
    
    test_hmac_incremental();
    test_hmac_edge_cases();
    test_hmac_security_properties();
    compare_hardware_vs_software();
    
    std::cout << "\n=== Test Summary ===\n";
    std::cout << "Overall result: " << (all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << "\n";
    
    return all_pass ? 0 : 1;
}