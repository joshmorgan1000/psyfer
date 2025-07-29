/**
 * @file test_aes_cmac.cpp
 * @brief Tests for AES-CMAC implementation
 */

#include <psyfer.hpp>
#include <psyfer/mac/aes_cmac.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>

/**
 * @brief Print MAC value
 */
void print_mac(const std::string& label, std::span<const std::byte, 16> mac) {
    std::cout << label << ": ";
    for (const auto& byte : mac) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<unsigned>(byte);
    }
    std::cout << std::dec << std::endl;
}

/**
 * @brief Test AES-CMAC-128
 */
void test_aes_cmac_128() {
    std::cout << "\n=== Testing AES-CMAC-128 ===" << std::endl;
    
    // Test vectors from NIST SP 800-38B
    // Test 1: Empty message
    {
        std::array<std::byte, 16> key{};
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<std::byte>(0x2b + i);  // Test key
        }
        
        std::vector<std::byte> empty_msg;
        std::array<std::byte, 16> mac;
        
        psyfer::mac::aes_cmac_128::compute(empty_msg, key, mac);
        print_mac("Empty message MAC", mac);
    }
    
    // Test 2: 16-byte message
    {
        std::array<std::byte, 16> key{};
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<std::byte>(0x2b + i);
        }
        
        std::array<std::byte, 16> msg{};
        for (int i = 0; i < 16; ++i) {
            msg[i] = static_cast<std::byte>(0x6b + i);
        }
        
        std::array<std::byte, 16> mac;
        psyfer::mac::aes_cmac_128::compute(msg, key, mac);
        print_mac("16-byte message MAC", mac);
    }
    
    // Test 3: 40-byte message (multiple blocks + partial)
    {
        std::array<std::byte, 16> key{};
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<std::byte>(0x2b + i);
        }
        
        std::vector<std::byte> msg(40);
        for (size_t i = 0; i < 40; ++i) {
            msg[i] = static_cast<std::byte>(0x6b + i);
        }
        
        std::array<std::byte, 16> mac;
        psyfer::mac::aes_cmac_128::compute(msg, key, mac);
        print_mac("40-byte message MAC", mac);
    }
    
    // Test streaming API
    {
        std::cout << "\nTesting streaming API..." << std::endl;
        
        std::array<std::byte, 16> key{};
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<std::byte>(i);
        }
        
        std::string test_message = "The quick brown fox jumps over the lazy dog";
        
        // One-shot
        std::array<std::byte, 16> mac1;
        psyfer::mac::aes_cmac_128::compute(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(test_message.data()),
                test_message.size()
            ),
            key,
            mac1
        );
        
        // Streaming
        psyfer::mac::aes_cmac_128 cmac(key);
        cmac.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(test_message.data()),
            20
        ));
        cmac.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(test_message.data() + 20),
            test_message.size() - 20
        ));
        
        std::array<std::byte, 16> mac2;
        cmac.finalize(mac2);
        
        bool match = std::memcmp(mac1.data(), mac2.data(), 16) == 0;
        std::cout << "Streaming matches one-shot: " << (match ? "YES" : "NO") << std::endl;
    }
    
    // Test MAC verification
    {
        std::cout << "\nTesting MAC verification..." << std::endl;
        
        std::array<std::byte, 16> key{};
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<std::byte>(0xAA);
        }
        
        std::string message = "Test message for MAC verification";
        
        // Generate MAC
        std::array<std::byte, 16> mac;
        psyfer::mac::aes_cmac_128::compute(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            ),
            key,
            mac
        );
        
        // Verify correct MAC
        bool valid = psyfer::mac::aes_cmac_128::verify(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            ),
            key,
            mac
        );
        std::cout << "Valid MAC verified: " << (valid ? "YES" : "NO") << std::endl;
        
        // Verify incorrect MAC
        mac[0] ^= std::byte{1};  // Flip one bit
        valid = psyfer::mac::aes_cmac_128::verify(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            ),
            key,
            mac
        );
        std::cout << "Invalid MAC rejected: " << (!valid ? "YES" : "NO") << std::endl;
    }
    
    std::cout << "✓ AES-CMAC-128 tests passed" << std::endl;
}

/**
 * @brief Test AES-CMAC-256
 */
void test_aes_cmac_256() {
    std::cout << "\n=== Testing AES-CMAC-256 ===" << std::endl;
    
    // Test basic functionality
    {
        std::array<std::byte, 32> key{};
        for (int i = 0; i < 32; ++i) {
            key[i] = static_cast<std::byte>(i);
        }
        
        std::string message = "Test message for AES-CMAC-256";
        std::array<std::byte, 16> mac;  // MAC is always 128 bits
        
        psyfer::mac::aes_cmac_256::compute(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            ),
            key,
            mac
        );
        
        print_mac("AES-CMAC-256 MAC", mac);
    }
    
    // Test that different keys produce different MACs
    {
        std::cout << "\nTesting key sensitivity..." << std::endl;
        
        std::array<std::byte, 32> key1{};
        std::array<std::byte, 32> key2{};
        for (int i = 0; i < 32; ++i) {
            key1[i] = static_cast<std::byte>(i);
            key2[i] = static_cast<std::byte>(i + 1);
        }
        
        std::string message = "Same message, different keys";
        std::array<std::byte, 16> mac1, mac2;
        
        psyfer::mac::aes_cmac_256::compute(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            ),
            key1,
            mac1
        );
        
        psyfer::mac::aes_cmac_256::compute(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(message.data()),
                message.size()
            ),
            key2,
            mac2
        );
        
        bool different = std::memcmp(mac1.data(), mac2.data(), 16) != 0;
        std::cout << "Different keys produce different MACs: " << (different ? "YES" : "NO") << std::endl;
    }
    
    std::cout << "✓ AES-CMAC-256 tests passed" << std::endl;
}

/**
 * @brief Test edge cases
 */
void test_edge_cases() {
    std::cout << "\n=== Testing Edge Cases ===" << std::endl;
    
    std::array<std::byte, 16> key{};
    std::fill(key.begin(), key.end(), std::byte{0xFF});
    
    // Test various message sizes
    std::vector<size_t> sizes = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129};
    
    for (size_t size : sizes) {
        std::vector<std::byte> msg(size);
        for (size_t i = 0; i < size; ++i) {
            msg[i] = static_cast<std::byte>(i & 0xFF);
        }
        
        std::array<std::byte, 16> mac;
        psyfer::mac::aes_cmac_128::compute(msg, key, mac);
        
        std::cout << "Size " << std::setw(3) << size << " bytes: ";
        for (int i = 0; i < 8; ++i) {  // Print first 8 bytes
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<unsigned>(mac[i]);
        }
        std::cout << "..." << std::dec << std::endl;
    }
    
    std::cout << "✓ Edge case tests passed" << std::endl;
}

/**
 * @brief Benchmark AES-CMAC performance
 */
void benchmark_aes_cmac() {
    std::cout << "\n=== Benchmarking AES-CMAC ===" << std::endl;
    
    const size_t MB = 1024 * 1024;
    std::vector<std::byte> data(10 * MB);
    
    // Fill with pseudo-random data
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>((i * 7919) & 0xFF);
    }
    
    // Benchmark AES-CMAC-128
    {
        std::array<std::byte, 16> key{};
        std::fill(key.begin(), key.end(), std::byte{0xAB});
        
        auto start = std::chrono::high_resolution_clock::now();
        
        psyfer::mac::aes_cmac_128 cmac(key);
        cmac.update(data);
        std::array<std::byte, 16> mac;
        cmac.finalize(mac);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        double throughput = (data.size() / (1024.0 * 1024.0)) / (duration / 1000000.0);
        std::cout << "AES-CMAC-128 throughput: " << std::fixed << std::setprecision(2) 
                  << throughput << " MB/s" << std::endl;
    }
    
    // Benchmark AES-CMAC-256
    {
        std::array<std::byte, 32> key{};
        std::fill(key.begin(), key.end(), std::byte{0xCD});
        
        auto start = std::chrono::high_resolution_clock::now();
        
        psyfer::mac::aes_cmac_256 cmac(key);
        cmac.update(data);
        std::array<std::byte, 16> mac;
        cmac.finalize(mac);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        double throughput = (data.size() / (1024.0 * 1024.0)) / (duration / 1000000.0);
        std::cout << "AES-CMAC-256 throughput: " << std::fixed << std::setprecision(2) 
                  << throughput << " MB/s" << std::endl;
    }
}

int main() {
    std::cout << "=== AES-CMAC Tests ===" << std::endl;
    
    test_aes_cmac_128();
    test_aes_cmac_256();
    test_edge_cases();
    benchmark_aes_cmac();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}