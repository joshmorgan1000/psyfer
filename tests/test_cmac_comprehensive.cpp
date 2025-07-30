/**
 * @file test_cmac_comprehensive.cpp
 * @brief Comprehensive test suite for AES-CMAC-128 and AES-CMAC-256
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cstring>

// Test vectors from RFC 4493 and NIST SP 800-38B
struct CMACTestVector {
    std::string name;
    std::vector<uint8_t> key;
    std::vector<uint8_t> data;
    std::vector<uint8_t> expected_cmac;
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

bool test_cmac_128() {
    std::cout << "\n=== AES-CMAC-128 Tests (RFC 4493) ===\n";
    
    // RFC 4493 Test Vectors
    std::vector<CMACTestVector> vectors = {
        {
            "Test 1: Empty message",
            hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
            {},
            hex_to_bytes("bb1d6929e95937287fa37d129b756746")
        },
        {
            "Test 2: 16 byte message",
            hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
            hex_to_bytes("6bc1bee22e409f96e93d7e117393172a"),
            hex_to_bytes("070a16b46b4d4144f79bdd9dd04a287c")
        },
        {
            "Test 3: 40 byte message",
            hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
            hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
            hex_to_bytes("dfa66747de9ae63030ca32611497c827")
        },
        {
            "Test 4: 64 byte message",
            hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
            hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
            hex_to_bytes("51f0bebf7e3b9d92fc49741779363cfe")
        }
    };
    
    bool all_pass = true;
    
    for (const auto& tv : vectors) {
        std::cout << "\n" << tv.name << ":\n";
        std::cout << "Key size: " << tv.key.size() << " bytes\n";
        std::cout << "Data size: " << tv.data.size() << " bytes\n";
        
        // Convert to byte spans
        std::array<std::byte, 16> key_bytes;
        std::memcpy(key_bytes.data(), tv.key.data(), 16);
        
        std::vector<std::byte> data_bytes(tv.data.size());
        if (!tv.data.empty()) {
            std::memcpy(data_bytes.data(), tv.data.data(), tv.data.size());
        }
        
        // Test CMAC-128
        std::array<std::byte, 16> cmac_output;
        psyfer::mac::aes_cmac_128::compute(data_bytes, key_bytes, cmac_output);
        
        bool pass = true;
        for (size_t i = 0; i < 16; ++i) {
            if (static_cast<uint8_t>(cmac_output[i]) != tv.expected_cmac[i]) {
                pass = false;
                break;
            }
        }
        
        print_hex("Computed", cmac_output);
        std::cout << "Expected: ";
        for (auto b : tv.expected_cmac) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        std::cout << std::dec << "\n";
        std::cout << "Result: " << (pass ? "PASS" : "FAIL") << "\n";
        
        if (!pass) all_pass = false;
        
        // Also test verification
        bool verified = psyfer::mac::aes_cmac_128::verify(data_bytes, key_bytes, cmac_output);
        std::cout << "Verification: " << (verified ? "PASS" : "FAIL") << "\n";
        
        if (!verified) all_pass = false;
    }
    
    return all_pass;
}

bool test_cmac_256() {
    std::cout << "\n=== AES-CMAC-256 Tests ===\n";
    
    // NIST SP 800-38B test vectors for AES-256
    std::vector<CMACTestVector> vectors = {
        {
            "Test 1: Empty message",
            hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            {},
            hex_to_bytes("028962f61b7bf89efc6b551f4667d983")
        },
        {
            "Test 2: 16 byte message",
            hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            hex_to_bytes("6bc1bee22e409f96e93d7e117393172a"),
            hex_to_bytes("28a7023f452e8f82bd4bf28d8c37c35c")
        },
        {
            "Test 3: 64 byte message",
            hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
            hex_to_bytes("e1992190549f6ed5696a2c056c315410")
        }
    };
    
    bool all_pass = true;
    
    for (const auto& tv : vectors) {
        std::cout << "\n" << tv.name << ":\n";
        std::cout << "Key size: " << tv.key.size() << " bytes\n";
        std::cout << "Data size: " << tv.data.size() << " bytes\n";
        
        // Convert to byte spans
        std::array<std::byte, 32> key_bytes;
        std::memcpy(key_bytes.data(), tv.key.data(), 32);
        
        std::vector<std::byte> data_bytes(tv.data.size());
        if (!tv.data.empty()) {
            std::memcpy(data_bytes.data(), tv.data.data(), tv.data.size());
        }
        
        // Test CMAC-256
        std::array<std::byte, 16> cmac_output;  // CMAC is always 128 bits
        psyfer::mac::aes_cmac_256::compute(data_bytes, key_bytes, cmac_output);
        
        bool pass = true;
        for (size_t i = 0; i < 16; ++i) {
            if (static_cast<uint8_t>(cmac_output[i]) != tv.expected_cmac[i]) {
                pass = false;
                break;
            }
        }
        
        print_hex("Computed", cmac_output);
        std::cout << "Expected: ";
        for (auto b : tv.expected_cmac) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        std::cout << std::dec << "\n";
        std::cout << "Result: " << (pass ? "PASS" : "FAIL") << "\n";
        
        if (!pass) all_pass = false;
    }
    
    return all_pass;
}

void test_cmac_incremental() {
    std::cout << "\n=== CMAC Incremental Update Tests ===\n";
    
    // Test that incremental updates produce same result as one-shot
    std::array<std::byte, 16> key;
    psyfer::utils::secure_random::generate(key);
    
    std::string test_data = "The quick brown fox jumps over the lazy dog. ";
    test_data += test_data; // Make it longer
    
    std::vector<std::byte> data(test_data.size());
    std::memcpy(data.data(), test_data.data(), test_data.size());
    
    // One-shot CMAC-128
    std::array<std::byte, 16> oneshot_result;
    psyfer::mac::aes_cmac_128::compute(data, key, oneshot_result);
    
    // Incremental CMAC-128
    psyfer::mac::aes_cmac_128 cmac(key);
    cmac.update(std::span<const std::byte>(data.data(), data.size() / 3));
    cmac.update(std::span<const std::byte>(data.data() + data.size() / 3, data.size() / 3));
    cmac.update(std::span<const std::byte>(data.data() + 2 * data.size() / 3, data.size() - 2 * data.size() / 3));
    
    std::array<std::byte, 16> incremental_result;
    cmac.finalize(incremental_result);
    
    bool match = std::memcmp(oneshot_result.data(), incremental_result.data(), 16) == 0;
    
    std::cout << "One-shot vs Incremental: " << (match ? "MATCH" : "MISMATCH") << "\n";
    print_hex("One-shot", oneshot_result);
    print_hex("Incremental", incremental_result);
}

void test_cmac_edge_cases() {
    std::cout << "\n=== CMAC Edge Cases ===\n";
    
    std::array<std::byte, 16> key;
    psyfer::utils::secure_random::generate(key);
    
    // Test various message sizes around block boundaries
    std::vector<size_t> test_sizes = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129};
    
    for (size_t size : test_sizes) {
        std::vector<std::byte> data(size);
        psyfer::utils::secure_random::generate(data);
        
        std::array<std::byte, 16> result;
        psyfer::mac::aes_cmac_128::compute(data, key, result);
        
        std::cout << "Size " << std::setw(3) << size << " bytes: ";
        print_hex("CMAC", std::span<const std::byte>(result.data(), 8)); // Just show first 8 bytes
    }
    
    // Test maximum size message (should handle gracefully)
    std::cout << "\nLarge message test (1MB):\n";
    std::vector<std::byte> large_data(1024 * 1024);
    psyfer::utils::secure_random::generate(std::span<std::byte>(large_data.data(), 1024)); // Just randomize first 1KB
    
    std::array<std::byte, 16> large_result;
    psyfer::mac::aes_cmac_128::compute(large_data, key, large_result);
    
    std::cout << "1MB CMAC computed successfully\n";
    print_hex("Result", std::span<const std::byte>(large_result.data(), 8));
}

void test_cmac_security_properties() {
    std::cout << "\n=== CMAC Security Properties ===\n";
    
    // Test that changing one bit changes output significantly
    std::array<std::byte, 16> key;
    psyfer::utils::secure_random::generate(key);
    
    std::vector<std::byte> data(64);
    psyfer::utils::secure_random::generate(data);
    
    std::array<std::byte, 16> result1;
    psyfer::mac::aes_cmac_128::compute(data, key, result1);
    
    // Change one bit in data
    data[0] = static_cast<std::byte>(static_cast<uint8_t>(data[0]) ^ 0x01);
    
    std::array<std::byte, 16> result2;
    psyfer::mac::aes_cmac_128::compute(data, key, result2);
    
    // Count different bits
    int different_bits = 0;
    for (size_t i = 0; i < 16; ++i) {
        uint8_t xor_result = static_cast<uint8_t>(result1[i]) ^ static_cast<uint8_t>(result2[i]);
        for (int bit = 0; bit < 8; ++bit) {
            if (xor_result & (1 << bit)) different_bits++;
        }
    }
    
    std::cout << "Data difference: 1 bit\n";
    std::cout << "CMAC difference: " << different_bits << " bits (out of 128)\n";
    std::cout << "Avalanche effect: " << (different_bits * 100.0 / 128.0) << "%\n";
    
    // Test key sensitivity
    std::array<std::byte, 16> key2 = key;
    key2[0] = static_cast<std::byte>(static_cast<uint8_t>(key2[0]) ^ 0x01);
    
    data[0] = static_cast<std::byte>(static_cast<uint8_t>(data[0]) ^ 0x01); // Restore original
    
    std::array<std::byte, 16> result3;
    psyfer::mac::aes_cmac_128::compute(data, key2, result3);
    
    different_bits = 0;
    for (size_t i = 0; i < 16; ++i) {
        uint8_t xor_result = static_cast<uint8_t>(result1[i]) ^ static_cast<uint8_t>(result3[i]);
        for (int bit = 0; bit < 8; ++bit) {
            if (xor_result & (1 << bit)) different_bits++;
        }
    }
    
    std::cout << "\nKey difference: 1 bit\n";
    std::cout << "CMAC difference: " << different_bits << " bits (out of 128)\n";
    std::cout << "Avalanche effect: " << (different_bits * 100.0 / 128.0) << "%\n";
}


void compare_hardware_vs_software() {
    std::cout << "\n=== Hardware vs Software Performance Comparison ===\n";
    
    const size_t iterations = 10000;
    const size_t data_size = 1024;
    
    std::array<std::byte, 16> key;
    psyfer::utils::secure_random::generate(key);
    
    std::vector<std::byte> data(data_size);
    psyfer::utils::secure_random::generate(data);
    
    std::array<std::byte, 16> result;
    
    // Test with hardware acceleration (if available)
    psyfer::config::disable_software_only();
    
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        psyfer::mac::aes_cmac_128::compute(data, key, result);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto hw_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Hardware-accelerated CMAC-128:\n";
    std::cout << "  " << iterations << " iterations in " << hw_duration.count() << " µs\n";
    std::cout << "  " << (iterations * 1000000.0) / hw_duration.count() << " ops/sec\n";
    
    // Save hardware result
    std::array<std::byte, 16> hw_result = result;
    
    // Test with software only
    psyfer::config::enable_software_only();
    
    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        psyfer::mac::aes_cmac_128::compute(data, key, result);
    }
    end = std::chrono::high_resolution_clock::now();
    auto sw_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "\nSoftware-only CMAC-128:\n";
    std::cout << "  " << iterations << " iterations in " << sw_duration.count() << " µs\n";
    std::cout << "  " << (iterations * 1000000.0) / sw_duration.count() << " ops/sec\n";
    
    // Verify results match
    bool results_match = std::memcmp(hw_result.data(), result.data(), 16) == 0;
    std::cout << "\nResults match: " << (results_match ? "YES" : "NO") << "\n";
    
    if (!results_match) {
        print_hex("Hardware", hw_result);
        print_hex("Software", result);
    }
    
    if (hw_duration < sw_duration) {
        double speedup = static_cast<double>(sw_duration.count()) / hw_duration.count();
        std::cout << "Hardware acceleration speedup: " << speedup << "x\n";
    }
    
    // Reset to default
    psyfer::config::disable_software_only();
}


int main() {
    std::cout << "=== AES-CMAC Comprehensive Test Suite ===\n";
    std::cout << "Testing AES-CMAC-128 and AES-CMAC-256 implementations\n";
    
    bool all_pass = true;
    
    // Run all tests
    all_pass &= test_cmac_128();
    all_pass &= test_cmac_256();
    
    test_cmac_incremental();
    test_cmac_edge_cases();
    test_cmac_security_properties();
    compare_hardware_vs_software();
    
    std::cout << "\n=== Test Summary ===\n";
    std::cout << "Overall result: " << (all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << "\n";
    
    return all_pass ? 0 : 1;
}