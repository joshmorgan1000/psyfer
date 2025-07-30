/**
 * @file 09_message_authentication.cpp
 * @brief Message authentication code (MAC) examples
 * 
 * This example demonstrates:
 * - HMAC with SHA-256/SHA-512
 * - AES-CMAC
 * - MAC verification
 * - Common MAC use cases
 * - MAC vs digital signatures
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstring>

using namespace psyfer;

/**
 * @brief Helper to print MAC values
 */
void print_mac(const std::string& label, std::span<const std::byte> mac) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(mac.size(), size_t(16)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<uint8_t>(mac[i]));
    }
    if (mac.size() > 16) {
        std::cout << "...";
    }
    std::cout << std::dec << " (" << mac.size() * 8 << " bits)\n";
}

/**
 * @brief Example 1: Basic HMAC-SHA256
 */
void example_hmac_sha256() {
    std::cout << "\n=== Example 1: HMAC-SHA256 ===\n";
    
    // Generate key
    auto key = utils::secure_key_256::generate();
    if (!key) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    
    // Message to authenticate
    std::string message = "Transfer $1000 from account 12345 to account 67890";
    std::cout << "Message: \"" << message << "\"\n";
    
    // Compute HMAC-SHA256
    std::array<std::byte, 32> hmac256;
    hash::hmac_sha256::hmac(
        key->span(),
        std::as_bytes(std::span(message)),
        hmac256
    );
    
    print_mac("HMAC-SHA256", hmac256);
    
    // Verify HMAC by recomputing
    std::array<std::byte, 32> verify_tag;
    hash::hmac_sha256::hmac(
        key->span(),
        std::as_bytes(std::span(message)),
        verify_tag
    );
    bool valid = (hmac256 == verify_tag);
    
    std::cout << "Verification: " << (valid ? "✅ VALID" : "❌ INVALID") << "\n";
    
    // Try with modified message
    std::string tampered = "Transfer $9000 from account 12345 to account 67890";
    std::array<std::byte, 32> tampered_tag;
    hash::hmac_sha256::hmac(
        key->span(),
        std::as_bytes(std::span(tampered)),
        tampered_tag
    );
    bool tampered_valid = (hmac256 == tampered_tag);
    
    std::cout << "\nTampered message: \"" << tampered << "\"\n";
    std::cout << "Tampered verification: " << (tampered_valid ? "❌ ACCEPTED (bad!)" : "✅ REJECTED") << "\n";
}

/**
 * @brief Example 2: HMAC-SHA512
 */
void example_hmac_sha512() {
    std::cout << "\n=== Example 2: HMAC-SHA512 ===\n";
    
    // HMAC-SHA512 uses 512-bit output
    auto key = utils::secure_key_512::generate();
    if (!key) return;
    
    std::string data = "High security message requiring strong authentication";
    
    // Compute HMAC-SHA512
    std::array<std::byte, 64> hmac512;
    hash::hmac_sha512::hmac(
        key->span(),
        std::as_bytes(std::span(data)),
        hmac512
    );
    
    std::cout << "Message: \"" << data << "\"\n";
    print_mac("HMAC-SHA512", hmac512);
    
    // Truncated MAC (first 32 bytes)
    std::array<std::byte, 32> truncated;
    std::memcpy(truncated.data(), hmac512.data(), 32);
    print_mac("Truncated (256-bit)", truncated);
    
    std::cout << "\nHMAC-SHA512 advantages:\n";
    std::cout << "  - Longer output (512 bits)\n";
    std::cout << "  - More resistant to length extension\n";
    std::cout << "  - Can be truncated if needed\n";
}

/**
 * @brief Example 3: AES-CMAC
 */
void example_aes_cmac() {
    std::cout << "\n=== Example 3: AES-CMAC ===\n";
    
    // AES-CMAC uses AES block cipher for MAC
    auto key128 = utils::secure_key_128::generate();
    if (!key128) return;
    
    std::string message = "Authenticated message using AES-based MAC";
    std::vector<std::byte> message_bytes(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    
    // Compute AES-128-CMAC
    std::array<std::byte, 16> cmac;
    mac::aes_cmac<16>::compute(message_bytes, key128->span(), cmac);
    
    std::cout << "Message: \"" << message << "\"\n";
    print_mac("AES-128-CMAC", cmac);
    
    // Verify
    bool valid = mac::aes_cmac<16>::verify(message_bytes, key128->span(), cmac);
    std::cout << "Self-verification: " << (valid ? "✅ VALID" : "❌ INVALID") << "\n";
    
    // AES-256-CMAC
    std::cout << "\n--- AES-256-CMAC ---\n";
    auto key256 = utils::secure_key_256::generate();
    if (!key256) return;
    
    mac::aes_cmac<32>::compute(message_bytes, key256->span(), cmac);
    
    print_mac("AES-256-CMAC", cmac);
    std::cout << "Note: Output is still 128 bits (AES block size)\n";
}

/**
 * @brief Example 4: Streaming MAC computation
 */
void example_streaming_mac() {
    std::cout << "\n=== Example 4: Streaming MAC ===\n";
    
    auto key = utils::secure_key_256::generate();
    if (!key) return;
    
    // Create HMAC instance
    hash::hmac_sha256 hmac(key->span());
    
    // Stream data in chunks
    std::vector<std::string> chunks = {
        "Part 1: The quick brown fox ",
        "Part 2: jumps over ",
        "Part 3: the lazy dog."
    };
    
    std::cout << "Streaming data:\n";
    for (const auto& chunk : chunks) {
        std::cout << "  - \"" << chunk << "\"\n";
        hmac.update(std::as_bytes(std::span(chunk)));
    }
    
    // Finalize MAC
    std::array<std::byte, 32> mac;
    hmac.finalize(mac);
    
    print_mac("Streamed HMAC", mac);
    
    // Compare with single-shot
    std::string full_message;
    for (const auto& chunk : chunks) {
        full_message += chunk;
    }
    
    std::array<std::byte, 32> single_mac;
    hash::hmac_sha256::hmac(
        key->span(),
        std::as_bytes(std::span(full_message)),
        single_mac
    );
    
    bool same = (mac == single_mac);
    std::cout << "Streaming vs single-shot: " << (same ? "✅ MATCH" : "❌ DIFFER") << "\n";
}

/**
 * @brief Example 5: File authentication
 */
void example_file_mac() {
    std::cout << "\n=== Example 5: File Authentication ===\n";
    
    // Create a test file
    std::string filename = "test_file.dat";
    {
        std::ofstream file(filename, std::ios::binary);
        file << "This is a test file for MAC verification.\n";
        file << "It contains important data that must not be tampered with.\n";
    }
    
    auto key = utils::secure_key_256::generate();
    if (!key) return;
    
    // Compute file MAC
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file\n";
        return;
    }
    
    hash::hmac_sha256 hmac(key->span());
    
    // Read and hash file in chunks
    constexpr size_t CHUNK_SIZE = 4096;
    std::vector<char> buffer(CHUNK_SIZE);
    
    while (file.read(buffer.data(), CHUNK_SIZE) || file.gcount() > 0) {
        hmac.update(std::as_bytes(std::span(buffer.data(), file.gcount())));
    }
    file.close();
    
    std::array<std::byte, 32> file_mac;
    hmac.finalize(file_mac);
    
    std::cout << "File: " << filename << "\n";
    print_mac("File MAC", file_mac);
    
    // Simulate file integrity check
    std::cout << "\nFile integrity check:\n";
    std::cout << "  Store MAC with file metadata\n";
    std::cout << "  Verify before processing file\n";
    std::cout << "  Detect any modifications\n";
    
    // Clean up
    std::remove(filename.c_str());
}

/**
 * @brief Example 6: MAC-based key derivation
 */
void example_mac_kdf() {
    std::cout << "\n=== Example 6: MAC-Based Key Derivation ===\n";
    
    // Master key
    auto master_key = utils::secure_key_256::generate();
    if (!master_key) return;
    
    // Derive multiple keys using HMAC
    std::vector<std::pair<std::string, std::array<std::byte, 32>>> derived_keys;
    
    std::vector<std::string> purposes = {
        "encryption-key",
        "signing-key",
        "storage-key"
    };
    
    for (const auto& purpose : purposes) {
        std::array<std::byte, 32> derived;
        
        // Simple KDF: HMAC(master_key, purpose)
        hash::hmac_sha256::hmac(
            master_key->span(),
            std::as_bytes(std::span(purpose)),
            derived
        );
        
        derived_keys.push_back({purpose, derived});
        std::cout << "Purpose: " << purpose << "\n";
        print_mac("  Derived", derived);
    }
    
    // Verify keys are different
    std::cout << "\nKey independence check:\n";
    for (size_t i = 0; i < derived_keys.size(); ++i) {
        for (size_t j = i + 1; j < derived_keys.size(); ++j) {
            bool different = (derived_keys[i].second != derived_keys[j].second);
            std::cout << "  " << derived_keys[i].first << " vs " 
                      << derived_keys[j].first << ": "
                      << (different ? "✅ Different" : "❌ Same (BAD!)") << "\n";
        }
    }
}

/**
 * @brief Example 7: Performance comparison
 */
void example_performance() {
    std::cout << "\n=== Example 7: MAC Performance ===\n";
    
    const size_t MESSAGE_SIZE = 1024 * 1024; // 1 MB
    const int ITERATIONS = 100;
    
    std::vector<std::byte> data(MESSAGE_SIZE);
    utils::secure_random::generate(data);
    
    // HMAC-SHA256
    {
        auto key = utils::secure_key_256::generate();
        if (!key) return;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < ITERATIONS; ++i) {
            std::array<std::byte, 32> mac;
            hash::hmac_sha256::hmac(key->span(), data, mac);
        }
        
        auto elapsed = std::chrono::high_resolution_clock::now() - start;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        
        double throughput = (MESSAGE_SIZE * ITERATIONS) / (ms / 1000.0) / (1024 * 1024);
        
        std::cout << "HMAC-SHA256:\n";
        std::cout << "  Time: " << ms << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(1) 
                  << throughput << " MB/s\n";
    }
    
    // HMAC-SHA512
    {
        auto key = utils::secure_key_512::generate();
        if (!key) return;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < ITERATIONS; ++i) {
            std::array<std::byte, 64> mac;
            hash::hmac_sha512::hmac(key->span(), data, mac);
        }
        
        auto elapsed = std::chrono::high_resolution_clock::now() - start;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        
        double throughput = (MESSAGE_SIZE * ITERATIONS) / (ms / 1000.0) / (1024 * 1024);
        
        std::cout << "\nHMAC-SHA512:\n";
        std::cout << "  Time: " << ms << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(1) 
                  << throughput << " MB/s\n";
    }
    
    // AES-CMAC
    {
        auto key = utils::secure_key_128::generate();
        if (!key) return;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < ITERATIONS; ++i) {
            std::array<std::byte, 16> mac;
            mac::aes_cmac<16>::compute(data, key->span(), mac);
        }
        
        auto elapsed = std::chrono::high_resolution_clock::now() - start;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        
        double throughput = (MESSAGE_SIZE * ITERATIONS) / (ms / 1000.0) / (1024 * 1024);
        
        std::cout << "\nAES-128-CMAC:\n";
        std::cout << "  Time: " << ms << " ms\n";
        std::cout << "  Throughput: " << std::fixed << std::setprecision(1) 
                  << throughput << " MB/s\n";
    }
}

/**
 * @brief Example 8: MAC vs Digital Signatures
 */
void example_mac_vs_signatures() {
    std::cout << "\n=== Example 8: MAC vs Digital Signatures ===\n";
    
    std::cout << "Message Authentication Codes (MACs):\n";
    std::cout << "  ✓ Fast computation\n";
    std::cout << "  ✓ Small output size\n";
    std::cout << "  ✓ Symmetric key (shared secret)\n";
    std::cout << "  ✗ Cannot prove authorship to third party\n";
    std::cout << "  ✗ Both parties can create valid MACs\n";
    
    std::cout << "\nDigital Signatures:\n";
    std::cout << "  ✓ Non-repudiation\n";
    std::cout << "  ✓ Public verifiability\n";
    std::cout << "  ✓ Proves specific sender\n";
    std::cout << "  ✗ Slower computation\n";
    std::cout << "  ✗ Larger signature size\n";
    
    // Demonstrate the difference
    auto mac_key = utils::secure_key_256::generate();
    if (!mac_key) return;
    
    std::string message = "Alice agrees to pay Bob $100";
    
    // MAC example
    std::array<std::byte, 32> mac;
    hash::hmac_sha256::hmac(
        mac_key->span(),
        std::as_bytes(std::span(message)),
        mac
    );
    
    std::cout << "\nExample scenario:\n";
    std::cout << "Message: \"" << message << "\"\n";
    print_mac("MAC", mac);
    std::cout << "  - Both Alice and Bob can create this MAC\n";
    std::cout << "  - Cannot prove to judge who created it\n";
    
    // Digital signature would be different
    std::cout << "\nWith digital signatures:\n";
    std::cout << "  - Only Alice's private key can create signature\n";
    std::cout << "  - Anyone can verify with Alice's public key\n";
    std::cout << "  - Provides legal non-repudiation\n";
}

int main() {
    std::cout << "Psyfer Message Authentication Examples\n";
    std::cout << "====================================\n";
    
    try {
        example_hmac_sha256();
        example_hmac_sha512();
        example_aes_cmac();
        example_streaming_mac();
        example_file_mac();
        example_mac_kdf();
        example_performance();
        example_mac_vs_signatures();
        
        std::cout << "\n✅ All MAC examples completed successfully!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}