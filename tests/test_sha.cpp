/**
 * @file test_sha.cpp
 * @brief Tests for SHA-256 and SHA-512 hash algorithms
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>

/**
 * @brief Print a byte array as hex
 */
void print_hex(const std::string& label, std::span<const std::byte> data) {
    std::cout << label << ": ";
    for (const auto& byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<unsigned int>(static_cast<uint8_t>(byte));
    }
    std::cout << std::dec << " (" << data.size() << " bytes)" << std::endl;
}

/**
 * @brief Test SHA-256 basic hashing
 */
void test_sha256_basic() {
    std::cout << "Testing SHA-256 basic hashing..." << std::endl;
    
    // Test empty string
    {
        std::array<std::byte, 32> hash;
        psyfer::hash::sha256::hash({}, hash);
        print_hex("Empty string hash", hash);
        
        // Known hash of empty string
        const char* expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        // Verify first few bytes
        assert(static_cast<uint8_t>(hash[0]) == 0xe3);
        assert(static_cast<uint8_t>(hash[1]) == 0xb0);
        assert(static_cast<uint8_t>(hash[2]) == 0xc4);
    }
    
    // Test "abc"
    {
        const char* input = "abc";
        std::array<std::byte, 32> hash;
        psyfer::hash::sha256::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(input), 3),
            hash
        );
        print_hex("SHA-256('abc')", hash);
        
        // Known hash: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert(static_cast<uint8_t>(hash[0]) == 0xba);
        assert(static_cast<uint8_t>(hash[1]) == 0x78);
        assert(static_cast<uint8_t>(hash[2]) == 0x16);
    }
    
    std::cout << "✓ SHA-256 basic tests passed" << std::endl;
}

/**
 * @brief Test SHA-512 basic hashing
 */
void test_sha512_basic() {
    std::cout << "\nTesting SHA-512 basic hashing..." << std::endl;
    
    // Test empty string
    {
        std::array<std::byte, 64> hash;
        psyfer::hash::sha512::hash({}, hash);
        print_hex("Empty string hash", hash);
        
        // Verify first few bytes of known hash
        assert(static_cast<uint8_t>(hash[0]) == 0xcf);
        assert(static_cast<uint8_t>(hash[1]) == 0x83);
        assert(static_cast<uint8_t>(hash[2]) == 0xe1);
    }
    
    // Test "abc"
    {
        const char* input = "abc";
        std::array<std::byte, 64> hash;
        psyfer::hash::sha512::hash(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(input), 3),
            hash
        );
        print_hex("SHA-512('abc')", hash);
        
        // Known hash starts with: ddaf35a193617aba...
        assert(static_cast<uint8_t>(hash[0]) == 0xdd);
        assert(static_cast<uint8_t>(hash[1]) == 0xaf);
        assert(static_cast<uint8_t>(hash[2]) == 0x35);
    }
    
    std::cout << "✓ SHA-512 basic tests passed" << std::endl;
}

/**
 * @brief Test incremental hashing
 */
void test_incremental_hashing() {
    std::cout << "\nTesting incremental hashing..." << std::endl;
    
    // SHA-256 incremental
    {
        psyfer::hash::sha256 hasher;
        
        const char* part1 = "Hello, ";
        const char* part2 = "World!";
        
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(part1), strlen(part1)
        ));
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(part2), strlen(part2)
        ));
        
        std::array<std::byte, 32> hash1;
        hasher.finalize(hash1);
        
        // Compare with one-shot
        std::string full = std::string(part1) + part2;
        std::array<std::byte, 32> hash2;
        psyfer::hash::sha256::hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(full.data()), 
                full.size()
            ),
            hash2
        );
        
        assert(std::memcmp(hash1.data(), hash2.data(), 32) == 0);
        std::cout << "✓ SHA-256 incremental matches one-shot" << std::endl;
    }
    
    // SHA-512 incremental
    {
        psyfer::hash::sha512 hasher;
        
        const char* part1 = "Hello, ";
        const char* part2 = "World!";
        
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(part1), strlen(part1)
        ));
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(part2), strlen(part2)
        ));
        
        std::array<std::byte, 64> hash1;
        hasher.finalize(hash1);
        
        // Compare with one-shot
        std::string full = std::string(part1) + part2;
        std::array<std::byte, 64> hash2;
        psyfer::hash::sha512::hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(full.data()), 
                full.size()
            ),
            hash2
        );
        
        assert(std::memcmp(hash1.data(), hash2.data(), 64) == 0);
        std::cout << "✓ SHA-512 incremental matches one-shot" << std::endl;
    }
}

/**
 * @brief Test HMAC-SHA256
 */
void test_hmac_sha256() {
    std::cout << "\nTesting HMAC-SHA256..." << std::endl;
    
    // Test with known vectors
    {
        // Key: "key"
        const char* key_str = "key";
        std::span<const std::byte> key(
            reinterpret_cast<const std::byte*>(key_str), 3
        );
        
        // Message: "The quick brown fox jumps over the lazy dog"
        const char* msg = "The quick brown fox jumps over the lazy dog";
        std::span<const std::byte> message(
            reinterpret_cast<const std::byte*>(msg), strlen(msg)
        );
        
        std::array<std::byte, 32> mac;
        psyfer::hash::hmac_sha256::hmac(key, message, mac);
        print_hex("HMAC-SHA256", mac);
        
        // Known HMAC starts with: f7bc83f4...
        assert(static_cast<uint8_t>(mac[0]) == 0xf7);
        assert(static_cast<uint8_t>(mac[1]) == 0xbc);
        assert(static_cast<uint8_t>(mac[2]) == 0x83);
    }
    
    std::cout << "✓ HMAC-SHA256 tests passed" << std::endl;
}

/**
 * @brief Test HMAC-SHA512
 */
void test_hmac_sha512() {
    std::cout << "\nTesting HMAC-SHA512..." << std::endl;
    
    // Test with known vectors
    {
        // Key: "key"
        const char* key_str = "key";
        std::span<const std::byte> key(
            reinterpret_cast<const std::byte*>(key_str), 3
        );
        
        // Message: "The quick brown fox jumps over the lazy dog"
        const char* msg = "The quick brown fox jumps over the lazy dog";
        std::span<const std::byte> message(
            reinterpret_cast<const std::byte*>(msg), strlen(msg)
        );
        
        std::array<std::byte, 64> mac;
        psyfer::hash::hmac_sha512::hmac(key, message, mac);
        print_hex("HMAC-SHA512", mac);
        
        // Known HMAC starts with: b42af09...
        assert(static_cast<uint8_t>(mac[0]) == 0xb4);
        assert(static_cast<uint8_t>(mac[1]) == 0x2a);
        assert(static_cast<uint8_t>(mac[2]) == 0xf0);
    }
    
    std::cout << "✓ HMAC-SHA512 tests passed" << std::endl;
}

/**
 * @brief Test hash reset functionality
 */
void test_hash_reset() {
    std::cout << "\nTesting hash reset..." << std::endl;
    
    // SHA-256 reset
    {
        psyfer::hash::sha256 hasher;
        
        // First hash
        const char* input1 = "first";
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(input1), strlen(input1)
        ));
        std::array<std::byte, 32> hash1;
        hasher.finalize(hash1);
        
        // Reset and hash something else
        hasher.reset();
        const char* input2 = "second";
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(input2), strlen(input2)
        ));
        std::array<std::byte, 32> hash2;
        hasher.finalize(hash2);
        
        // Direct hash of "second"
        std::array<std::byte, 32> hash3;
        psyfer::hash::sha256::hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(input2), strlen(input2)
            ),
            hash3
        );
        
        // hash2 should match hash3, not hash1
        assert(std::memcmp(hash1.data(), hash2.data(), 32) != 0);
        assert(std::memcmp(hash2.data(), hash3.data(), 32) == 0);
        
        std::cout << "✓ SHA-256 reset works correctly" << std::endl;
    }
}

int main() {
    std::cout << "=== SHA-256/512 Hash Tests ===" << std::endl;
    
    test_sha256_basic();
    test_sha512_basic();
    test_incremental_hashing();
    test_hmac_sha256();
    test_hmac_sha512();
    test_hash_reset();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}