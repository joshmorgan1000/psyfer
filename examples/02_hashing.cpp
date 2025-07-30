/**
 * @file 02_hashing.cpp
 * @brief Comprehensive hashing examples
 * 
 * This example demonstrates:
 * - SHA-256 and SHA-512 cryptographic hashing
 * - HMAC-SHA256 and HMAC-SHA512 for message authentication
 * - xxHash3 for fast non-cryptographic hashing (24/32/64/128-bit)
 * - Streaming vs one-shot hashing
 * - Hash-based data structures
 * - Performance comparisons
 */

#include <psyfer.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <unordered_map>

using namespace psyfer;

/**
 * @brief Helper to print hash as hexadecimal
 */
void print_hash(const std::string& label, std::span<const std::byte> hash) {
    std::cout << label << ": ";
    for (auto b : hash) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(static_cast<uint8_t>(b));
    }
    std::cout << std::dec << "\n";
}

/**
 * @brief Example 1: Basic SHA-256 hashing
 */
void example_sha256_basic() {
    std::cout << "\n=== Example 1: SHA-256 Hashing ===\n";
    
    // Method 1: One-shot hashing
    std::string message = "Hello, Psyfer!";
    std::vector<std::byte> data(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    std::array<std::byte, 32> hash;
    
    hash::sha256::hash(data, hash);
    
    std::cout << "Message: " << message << "\n";
    print_hash("SHA-256", hash);
    
    // Method 2: Streaming hash (useful for large files or streaming data)
    std::cout << "\nStreaming hash example:\n";
    hash::sha256 hasher;
    
    // Hash data in chunks
    std::string part1 = "Hello, ";
    std::string part2 = "Psyfer!";
    
    hasher.update(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(part1.data()), part1.size()
    ));
    hasher.update(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(part2.data()), part2.size()
    ));
    
    std::array<std::byte, 32> streaming_hash;
    hasher.finalize(streaming_hash);
    
    print_hash("Streaming SHA-256", streaming_hash);
    std::cout << "Hashes match: " << (hash == streaming_hash ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 2: SHA-512 for higher security requirements
 */
void example_sha512() {
    std::cout << "\n=== Example 2: SHA-512 Hashing ===\n";
    
    std::string data = "SHA-512 provides 512-bit output for applications requiring higher security margins";
    std::array<std::byte, 64> hash;
    
    hash::sha512::hash(
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(data.data()), 
            data.size()
        ), 
        hash
    );
    
    std::cout << "Data: " << data.substr(0, 50) << "...\n";
    print_hash("SHA-512 (first 32 bytes)", std::span(hash).first(32));
    std::cout << "Full hash size: " << hash.size() << " bytes\n";
}

/**
 * @brief Example 3: HMAC for message authentication
 */
void example_hmac() {
    std::cout << "\n=== Example 3: HMAC Message Authentication ===\n";
    
    // HMAC provides authentication and integrity
    // Use case: API authentication, message integrity verification
    
    // Generate a secret key
    auto key_result = utils::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    std::string message = "{'user': 'alice', 'action': 'transfer', 'amount': 1000}";
    
    // Create HMAC-SHA256
    std::array<std::byte, 32> mac;
    hash::hmac_sha256::hmac(
        key.span(),
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        ),
        mac
    );
    
    std::cout << "Message: " << message << "\n";
    print_hash("HMAC-SHA256", mac);
    
    // Verify HMAC (simulating receiver)
    std::array<std::byte, 32> verify_mac;
    hash::hmac_sha256::hmac(
        key.span(),
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(message.data()),
            message.size()
        ),
        verify_mac
    );
    
    bool valid = (mac == verify_mac);
    std::cout << "MAC verification: " << (valid ? "✅ VALID" : "❌ INVALID") << "\n";
    
    // Demonstrate tampering detection
    std::cout << "\nTampering detection:\n";
    std::string tampered = "{'user': 'alice', 'action': 'transfer', 'amount': 9999}";
    
    hash::hmac_sha256::hmac(
        key.span(),
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(tampered.data()),
            tampered.size()
        ),
        verify_mac
    );
    
    valid = (mac == verify_mac);
    std::cout << "Tampered message verification: " << (valid ? "❌ VALID (bad!)" : "✅ INVALID (good!)") << "\n";
}

/**
 * @brief Example 4: xxHash3 for fast non-cryptographic hashing
 */
void example_xxhash3() {
    std::cout << "\n=== Example 4: xxHash3 Fast Hashing ===\n";
    
    // xxHash3 is extremely fast but NOT cryptographically secure
    // Use cases: hash tables, checksums, deduplication, caching
    
    std::string data = "Fast non-cryptographic hashing with xxHash3";
    std::span<const std::byte> bytes(
        reinterpret_cast<const std::byte*>(data.data()),
        data.size()
    );
    
    // 32-bit hash (good for hash tables with ~4 billion entries)
    uint32_t hash32 = hash::xxh3_32::hash(bytes);
    std::cout << "xxHash3-32: 0x" << std::hex << hash32 << std::dec << "\n";
    
    // 64-bit hash (good for larger hash tables)
    uint64_t hash64 = hash::xxh3_64::hash(bytes);
    std::cout << "xxHash3-64: 0x" << std::hex << hash64 << std::dec << "\n";
    
    // 128-bit hash (when you need really low collision probability)
    auto hash128 = hash::xxh3_128::hash(bytes);
    std::cout << "xxHash3-128: 0x" << std::hex << hash128.high << hash128.low << std::dec << "\n";
    
    // Custom seed for different hash values
    uint64_t custom_seed = 42;
    uint64_t seeded_hash = hash::xxh3_64::hash(bytes, custom_seed);
    std::cout << "xxHash3-64 with seed 42: 0x" << std::hex << seeded_hash << std::dec << "\n";
}

/**
 * @brief Example 5: Hash table using xxHash3
 */
void example_hash_table() {
    std::cout << "\n=== Example 5: Custom Hash Table with xxHash3 ===\n";
    
    // Custom hasher for std::unordered_map
    struct XxHash3Hasher {
        size_t operator()(const std::string& key) const {
            return hash::xxh3_64::hash(key);
        }
    };
    
    // Create hash table with custom hasher
    std::unordered_map<std::string, int, XxHash3Hasher> fast_map;
    
    // Insert some data
    std::vector<std::string> keys = {
        "apple", "banana", "cherry", "date", "elderberry",
        "fig", "grape", "honeydew", "kiwi", "lemon"
    };
    
    for (size_t i = 0; i < keys.size(); ++i) {
        fast_map[keys[i]] = i * 100;
    }
    
    // Lookup
    std::cout << "Hash table lookups:\n";
    for (const auto& key : {"apple", "grape", "mango"}) {
        auto it = fast_map.find(key);
        if (it != fast_map.end()) {
            std::cout << "  " << key << " -> " << it->second << "\n";
        } else {
            std::cout << "  " << key << " -> not found\n";
        }
    }
    
    // Show hash distribution
    std::cout << "\nHash values (showing distribution):\n";
    for (size_t i = 0; i < 5; ++i) {
        uint64_t h = hash::xxh3_64::hash(keys[i]);
        std::cout << "  " << keys[i] << ": " << (h % 1000) << "\n";
    }
}

/**
 * @brief Example 6: File hashing and integrity checking
 */
void example_file_hashing() {
    std::cout << "\n=== Example 6: File Hashing and Integrity ===\n";
    
    // Create a test file
    std::string filename = "test_file.txt";
    {
        std::ofstream file(filename);
        file << "This is a test file for hashing.\n";
        file << "It contains multiple lines of text.\n";
        file << "We'll use it to demonstrate file integrity checking.\n";
    }
    
    // Hash the file using streaming
    hash::sha256 hasher;
    std::ifstream file(filename, std::ios::binary);
    
    if (!file) {
        std::cerr << "Failed to open file\n";
        return;
    }
    
    // Read and hash in chunks
    constexpr size_t CHUNK_SIZE = 4096;
    std::vector<char> buffer(CHUNK_SIZE);
    
    while (file.read(buffer.data(), CHUNK_SIZE) || file.gcount() > 0) {
        size_t bytes_read = file.gcount();
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(buffer.data()),
            bytes_read
        ));
    }
    
    std::array<std::byte, 32> file_hash;
    hasher.finalize(file_hash);
    
    std::cout << "File: " << filename << "\n";
    print_hash("SHA-256", file_hash);
    
    // Simulate integrity check
    std::cout << "\nIntegrity check:\n";
    std::cout << "Store this hash with your file for later verification\n";
    std::cout << "If the file is modified, the hash will change\n";
    
    // Clean up
    file.close();
    std::remove(filename.c_str());
}

/**
 * @brief Example 7: Performance comparison
 */
void example_performance() {
    std::cout << "\n=== Example 7: Hash Performance Comparison ===\n";
    
    // Generate test data
    std::vector<std::byte> data(1'000'000);  // 1 MB
    utils::secure_random::generate(data);
    
    const int iterations = 100;
    
    // Benchmark SHA-256
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; ++i) {
            std::array<std::byte, 32> hash;
            hash::sha256::hash(data, hash);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        double throughput = (data.size() * iterations) / (duration.count() / 1e6) / 1e6;
        std::cout << "SHA-256:    " << std::fixed << std::setprecision(1) 
                  << throughput << " MB/s\n";
    }
    
    // Benchmark SHA-512
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; ++i) {
            std::array<std::byte, 64> hash;
            hash::sha512::hash(data, hash);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        double throughput = (data.size() * iterations) / (duration.count() / 1e6) / 1e6;
        std::cout << "SHA-512:    " << std::fixed << std::setprecision(1) 
                  << throughput << " MB/s\n";
    }
    
    // Benchmark xxHash3-64
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; ++i) {
            uint64_t hash = hash::xxh3_64::hash(data);
            (void)hash;  // Prevent optimization
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        double throughput = (data.size() * iterations) / (duration.count() / 1e6) / 1e6;
        std::cout << "xxHash3-64: " << std::fixed << std::setprecision(1) 
                  << throughput << " MB/s\n";
    }
    
    std::cout << "\nNote: xxHash3 is much faster but NOT cryptographically secure!\n";
}

/**
 * @brief Example 8: Password hashing (using PBKDF2-like approach)
 */
void example_password_hashing() {
    std::cout << "\n=== Example 8: Password Hashing ===\n";
    
    // For password hashing, we need:
    // 1. Salt (random data to prevent rainbow tables)
    // 2. Multiple iterations (to slow down brute force)
    // 3. Secure hash function
    
    std::string password = "mysecretpassword";
    
    // Generate a random salt
    std::array<std::byte, 16> salt;
    utils::secure_random::generate(salt);
    
    std::cout << "Password: " << password << "\n";
    print_hash("Salt", salt);
    
    // Simple PBKDF2-like implementation using HMAC-SHA256
    // (In production, use a proper PBKDF2, scrypt, or Argon2 implementation)
    const int iterations = 10000;
    
    // Initial HMAC with password as key and salt as data
    std::array<std::byte, 32> derived_key;
    std::span<const std::byte> password_bytes(
        reinterpret_cast<const std::byte*>(password.data()),
        password.size()
    );
    
    // Note: This is a simplified version. Real PBKDF2 is more complex.
    hash::hmac_sha256 hmac(password_bytes);
    hmac.update(salt);
    
    // Iterate to increase computational cost
    std::array<std::byte, 32> temp;
    hmac.finalize(temp);
    
    for (int i = 1; i < iterations; ++i) {
        hmac.reset();
        hmac.update(temp);
        hmac.finalize(temp);
    }
    
    derived_key = temp;
    
    print_hash("Derived key", derived_key);
    std::cout << "Iterations: " << iterations << "\n";
    std::cout << "\nThis derived key can be stored in the database.\n";
    std::cout << "To verify, repeat the process with the same salt and compare.\n";
}

int main() {
    std::cout << "Psyfer Hashing Examples\n";
    std::cout << "======================\n";
    
    try {
        example_sha256_basic();
        example_sha512();
        example_hmac();
        example_xxhash3();
        example_hash_table();
        example_file_hashing();
        example_performance();
        example_password_hashing();
        
        std::cout << "\n✅ All hashing examples completed successfully!\n";
        
        std::cout << "\nKey Takeaways:\n";
        std::cout << "1. Use SHA-256/512 for cryptographic hashing\n";
        std::cout << "2. Use HMAC for message authentication\n";
        std::cout << "3. Use xxHash3 for non-cryptographic fast hashing\n";
        std::cout << "4. Always use proper password hashing libraries in production\n";
        std::cout << "5. Consider streaming hashes for large files\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}