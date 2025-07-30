/**
 * @file 07_authenticated_encryption.cpp
 * @brief Authenticated encryption (AEAD) examples
 * 
 * This example demonstrates:
 * - AEAD cipher modes (AES-GCM, ChaCha20-Poly1305)
 * - Additional authenticated data (AAD)
 * - Nonce generation and management
 * - Tag verification
 * - Common AEAD use cases
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

using namespace psyfer;

/**
 * @brief Helper to print hex data
 */
void print_hex(const std::string& label, std::span<const std::byte> data, size_t limit = 16) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(data.size(), limit); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<uint8_t>(data[i]));
    }
    if (data.size() > limit) std::cout << "...";
    std::cout << std::dec << "\n";
}

/**
 * @brief Example 1: Basic AES-GCM usage
 */
void example_aes_gcm_basic() {
    std::cout << "\n=== Example 1: Basic AES-GCM ===\n";
    
    // Generate key
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto& key = *key_result;
    
    // Create cipher
    psyfer::aes256_gcm cipher;
    
    // Prepare data
    std::string message = "This is a secret message that needs authentication";
    std::vector<std::byte> plaintext(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    
    // Generate nonce (96 bits for GCM)
    std::array<std::byte, 12> nonce;
    secure_random::generate(nonce);
    
    // Tag will be computed during encryption
    std::array<std::byte, 16> tag;
    
    std::cout << "Message: \"" << message << "\"\n";
    print_hex("Key", key.span());
    print_hex("Nonce", nonce);
    
    // Encrypt
    auto err = cipher.encrypt(plaintext, key.span(), nonce, tag);
    if (err) {
        std::cerr << "Encryption failed: " << err.message() << "\n";
        return;
    }
    
    print_hex("Ciphertext", plaintext);
    print_hex("Tag", tag);
    
    // Decrypt
    err = cipher.decrypt(plaintext, key.span(), nonce, tag);
    if (err) {
        std::cerr << "Decryption failed: " << err.message() << "\n";
        return;
    }
    
    std::string decrypted(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    std::cout << "Decrypted: \"" << decrypted << "\"\n";
    std::cout << "Authentication: ✅ VERIFIED\n";
}

/**
 * @brief Example 2: Using additional authenticated data (AAD)
 */
void example_aead_with_aad() {
    std::cout << "\n=== Example 2: AEAD with Additional Authenticated Data ===\n";
    
    // Scenario: Encrypting a message with metadata
    struct Message {
        std::string sender = "alice@example.com";
        std::string recipient = "bob@example.com";
        uint64_t timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        std::string content = "Meet me at the usual place";
    };
    
    Message msg;
    
    // The content will be encrypted, metadata will be authenticated but not encrypted
    std::vector<std::byte> plaintext(
        reinterpret_cast<const std::byte*>(msg.content.data()),
        reinterpret_cast<const std::byte*>(msg.content.data() + msg.content.size())
    );
    
    // Build AAD from metadata
    std::stringstream aad_stream;
    aad_stream << msg.sender << "|" << msg.recipient << "|" << msg.timestamp;
    std::string aad_str = aad_stream.str();
    std::vector<std::byte> aad(
        reinterpret_cast<const std::byte*>(aad_str.data()),
        reinterpret_cast<const std::byte*>(aad_str.data() + aad_str.size())
    );
    
    std::cout << "Sender: " << msg.sender << "\n";
    std::cout << "Recipient: " << msg.recipient << "\n";
    std::cout << "Timestamp: " << msg.timestamp << "\n";
    std::cout << "Content: \"" << msg.content << "\"\n";
    std::cout << "AAD: \"" << aad_str << "\"\n";
    
    // Encrypt with AAD
    auto key = psyfer::secure_key_256::generate();
    if (!key) return;
    
    psyfer::aes256_gcm cipher;
    std::array<std::byte, 12> nonce;
    std::array<std::byte, 16> tag;
    secure_random::generate(nonce);
    
    auto err = cipher.encrypt(plaintext, key->span(), nonce, tag, aad);
    if (err) {
        std::cerr << "Encryption failed: " << err.message() << "\n";
        return;
    }
    
    std::cout << "\nEncrypted content, authenticated metadata\n";
    print_hex("Tag", tag);
    
    // Verify with correct AAD
    std::vector<std::byte> ciphertext = plaintext; // Save for tampering test
    err = cipher.decrypt(plaintext, key->span(), nonce, tag, aad);
    if (!err) {
        std::cout << "Verification with correct AAD: ✅ SUCCESS\n";
    }
    
    // Try with tampered AAD
    aad[0] = std::byte{'e'}; // Change 'a' to 'e' in alice
    plaintext = ciphertext; // Restore ciphertext
    err = cipher.decrypt(plaintext, key->span(), nonce, tag, aad);
    if (err) {
        std::cout << "Verification with tampered AAD: ✅ REJECTED (correct behavior)\n";
    }
}

/**
 * @brief Example 3: ChaCha20-Poly1305
 */
void example_chacha20_poly1305() {
    std::cout << "\n=== Example 3: ChaCha20-Poly1305 ===\n";
    
    psyfer::chacha20_poly1305 cipher;
    
    // ChaCha20-Poly1305 specifics
    std::cout << "ChaCha20-Poly1305 characteristics:\n";
    std::cout << "  - 256-bit key\n";
    std::cout << "  - 96-bit nonce\n";
    std::cout << "  - 128-bit authentication tag\n";
    std::cout << "  - Faster than AES-GCM on systems without AES-NI\n";
    
    // Generate key
    auto key = psyfer::secure_key_256::generate();
    if (!key) return;
    
    // Test data
    std::string data = "ChaCha20-Poly1305 is a modern AEAD cipher";
    std::vector<std::byte> plaintext(
        reinterpret_cast<const std::byte*>(data.data()),
        reinterpret_cast<const std::byte*>(data.data() + data.size())
    );
    
    std::array<std::byte, 12> nonce;
    std::array<std::byte, 16> tag;
    secure_random::generate(nonce);
    
    // Encrypt
    auto start = std::chrono::high_resolution_clock::now();
    
    auto err = cipher.encrypt(plaintext, key->span(), nonce, tag);
    if (err) {
        std::cerr << "Encryption failed\n";
        return;
    }
    
    auto enc_time = std::chrono::high_resolution_clock::now() - start;
    
    std::cout << "\nOriginal: \"" << data << "\"\n";
    print_hex("Encrypted", plaintext);
    print_hex("Tag", tag);
    
    // Decrypt
    start = std::chrono::high_resolution_clock::now();
    
    err = cipher.decrypt(plaintext, key->span(), nonce, tag);
    
    auto dec_time = std::chrono::high_resolution_clock::now() - start;
    
    if (!err) {
        std::string decrypted(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
        std::cout << "Decrypted: \"" << decrypted << "\"\n";
        
        std::cout << "\nPerformance:\n";
        std::cout << "  Encryption: " << std::chrono::duration_cast<std::chrono::microseconds>(enc_time).count() << " µs\n";
        std::cout << "  Decryption: " << std::chrono::duration_cast<std::chrono::microseconds>(dec_time).count() << " µs\n";
    }
}

/**
 * @brief Example 4: Nonce management strategies
 */
void example_nonce_management() {
    std::cout << "\n=== Example 4: Nonce Management ===\n";
    
    // Strategy 1: Random nonces
    {
        std::cout << "Strategy 1: Random nonces\n";
        
        psyfer::aes256_gcm cipher;
        auto key = psyfer::secure_key_256::generate();
        if (!key) return;
        
        // Can safely use random nonces with 96-bit size
        for (int i = 0; i < 3; ++i) {
            std::array<std::byte, 12> nonce;
            secure_random::generate(nonce);
            
            std::cout << "  Message " << i << " nonce: ";
            for (size_t j = 0; j < 4; ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(static_cast<uint8_t>(nonce[j]));
            }
            std::cout << "...\n";
        }
        std::cout << std::dec;
    }
    
    // Strategy 2: Counter-based nonces
    {
        std::cout << "\nStrategy 2: Counter-based nonces\n";
        
        struct NonceCounter {
            std::array<std::byte, 12> nonce{};
            uint64_t counter = 0;
            
            void increment() {
                counter++;
                // Store counter in last 8 bytes
                std::memcpy(nonce.data() + 4, &counter, sizeof(counter));
            }
            
            std::array<std::byte, 12> get() {
                increment();
                return nonce;
            }
        };
        
        NonceCounter nc;
        // Set random prefix
        secure_random::generate(std::span(nc.nonce.data(), 4));
        
        for (int i = 0; i < 3; ++i) {
            auto nonce = nc.get();
            std::cout << "  Message " << i << " nonce: ";
            for (size_t j = 0; j < 12; ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(static_cast<uint8_t>(nonce[j]));
            }
            std::cout << std::dec << "\n";
        }
    }
    
    // Strategy 3: Time-based nonces
    {
        std::cout << "\nStrategy 3: Time-based nonces\n";
        
        auto generate_time_nonce = []() {
            std::array<std::byte, 12> nonce{};
            auto now = std::chrono::system_clock::now().time_since_epoch();
            auto micros = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
            
            // First 8 bytes: timestamp
            std::memcpy(nonce.data(), &micros, sizeof(micros));
            
            // Last 4 bytes: random
            secure_random::generate(std::span(nonce.data() + 8, 4));
            
            return nonce;
        };
        
        for (int i = 0; i < 3; ++i) {
            auto nonce = generate_time_nonce();
            std::cout << "  Nonce " << i << ": ";
            for (size_t j = 0; j < 6; ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(static_cast<uint8_t>(nonce[j]));
            }
            std::cout << "...\n";
            
            // Small delay to ensure different timestamps
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        std::cout << std::dec;
    }
}

/**
 * @brief Example 5: Tag truncation and verification
 */
void example_tag_verification() {
    std::cout << "\n=== Example 5: Authentication Tag Handling ===\n";
    
    psyfer::aes256_gcm cipher;
    auto key = psyfer::secure_key_256::generate();
    if (!key) return;
    
    std::string message = "Important message requiring authentication";
    std::vector<std::byte> plaintext(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    std::array<std::byte, 12> nonce;
    std::array<std::byte, 16> tag;
    secure_random::generate(nonce);
    
    // Encrypt
    cipher.encrypt(plaintext, key->span(), nonce, tag);
    
    std::cout << "Original message: \"" << message << "\"\n";
    print_hex("Authentication tag", tag);
    
    // Save ciphertext for tests
    std::vector<std::byte> ciphertext = plaintext;
    
    // Test 1: Correct tag
    plaintext = ciphertext;
    auto err = cipher.decrypt(plaintext, key->span(), nonce, tag);
    std::cout << "\nCorrect tag verification: " << (!err ? "✅ PASS" : "❌ FAIL") << "\n";
    
    // Test 2: Modified tag (flip one bit)
    plaintext = ciphertext;
    tag[0] ^= std::byte{0x01};
    err = cipher.decrypt(plaintext, key->span(), nonce, tag);
    std::cout << "Modified tag verification: " << (err ? "✅ REJECTED" : "❌ ACCEPTED (bad!)") << "\n";
    tag[0] ^= std::byte{0x01}; // Restore
    
    // Test 3: Modified ciphertext
    plaintext = ciphertext;
    plaintext[0] ^= std::byte{0x01};
    err = cipher.decrypt(plaintext, key->span(), nonce, tag);
    std::cout << "Modified ciphertext verification: " << (err ? "✅ REJECTED" : "❌ ACCEPTED (bad!)") << "\n";
    
    // Test 4: Wrong nonce
    plaintext = ciphertext;
    nonce[0] ^= std::byte{0x01};
    err = cipher.decrypt(plaintext, key->span(), nonce, tag);
    std::cout << "Wrong nonce verification: " << (err ? "✅ REJECTED" : "❌ ACCEPTED (bad!)") << "\n";
}

/**
 * @brief Example 6: Streaming AEAD
 */
void example_streaming_aead() {
    std::cout << "\n=== Example 6: Streaming Authenticated Encryption ===\n";
    
    // Simulate encrypting a large file in chunks
    const size_t CHUNK_SIZE = 4096;
    const size_t TOTAL_SIZE = 10000;
    
    psyfer::aes256_gcm cipher;
    auto key = psyfer::secure_key_256::generate();
    if (!key) return;
    
    // Each chunk gets its own nonce and tag
    struct AuthenticatedChunk {
        std::array<std::byte, 12> nonce;
        std::vector<std::byte> data;
        std::array<std::byte, 16> tag;
    };
    
    std::vector<AuthenticatedChunk> chunks;
    
    // Generate test data
    std::string test_data(TOTAL_SIZE, 'A');
    for (size_t i = 0; i < TOTAL_SIZE; ++i) {
        test_data[i] = 'A' + (i % 26);
    }
    
    std::cout << "Encrypting " << TOTAL_SIZE << " bytes in " << CHUNK_SIZE << "-byte chunks\n";
    
    // Encrypt in chunks
    size_t offset = 0;
    size_t chunk_count = 0;
    
    while (offset < TOTAL_SIZE) {
        size_t chunk_len = std::min(CHUNK_SIZE, TOTAL_SIZE - offset);
        
        AuthenticatedChunk chunk;
        secure_random::generate(chunk.nonce);
        
        // Copy chunk data
        chunk.data.assign(
            reinterpret_cast<const std::byte*>(test_data.data() + offset),
            reinterpret_cast<const std::byte*>(test_data.data() + offset + chunk_len)
        );
        
        // Add chunk metadata as AAD
        std::string aad_str = "chunk:" + std::to_string(chunk_count) + ",offset:" + std::to_string(offset);
        std::vector<std::byte> aad(
        reinterpret_cast<const std::byte*>(aad_str.data()),
        reinterpret_cast<const std::byte*>(aad_str.data() + aad_str.size())
    );
        
        // Encrypt chunk
        auto err = cipher.encrypt(chunk.data, key->span(), chunk.nonce, chunk.tag, aad);
        if (!err) {
            chunks.push_back(std::move(chunk));
            chunk_count++;
        }
        
        offset += chunk_len;
    }
    
    std::cout << "Created " << chunks.size() << " authenticated chunks\n";
    
    // Decrypt and verify chunks
    std::string reconstructed;
    reconstructed.reserve(TOTAL_SIZE);
    
    for (size_t i = 0; i < chunks.size(); ++i) {
        auto& chunk = chunks[i];
        
        // Rebuild AAD
        std::string aad_str = "chunk:" + std::to_string(i) + ",offset:" + std::to_string(reconstructed.size());
        std::vector<std::byte> aad(
        reinterpret_cast<const std::byte*>(aad_str.data()),
        reinterpret_cast<const std::byte*>(aad_str.data() + aad_str.size())
    );
        
        // Decrypt
        auto err = cipher.decrypt(chunk.data, key->span(), chunk.nonce, chunk.tag, aad);
        if (!err) {
            reconstructed.append(
                reinterpret_cast<char*>(chunk.data.data()),
                chunk.data.size()
            );
        } else {
            std::cerr << "Failed to decrypt chunk " << i << "\n";
        }
    }
    
    std::cout << "Reconstructed " << reconstructed.size() << " bytes\n";
    std::cout << "Data integrity: " << (reconstructed == test_data ? "✅ VERIFIED" : "❌ CORRUPTED") << "\n";
}

/**
 * @brief Example 7: AEAD cipher comparison
 */
void example_cipher_comparison() {
    std::cout << "\n=== Example 7: AEAD Cipher Comparison ===\n";
    
    auto key = psyfer::secure_key_256::generate();
    if (!key) return;
    
    // Test data of various sizes
    std::vector<size_t> test_sizes = {16, 64, 256, 1024, 4096};
    
    for (size_t size : test_sizes) {
        std::cout << "\nData size: " << size << " bytes\n";
        
        std::vector<std::byte> data(size);
        secure_random::generate(data);
        
        // AES-256-GCM
        {
            psyfer::aes256_gcm cipher;
            std::vector<std::byte> test_data = data;
            std::array<std::byte, 12> nonce;
            std::array<std::byte, 16> tag;
            secure_random::generate(nonce);
            
            auto start = std::chrono::high_resolution_clock::now();
            cipher.encrypt(test_data, key->span(), nonce, tag);
            auto enc_time = std::chrono::high_resolution_clock::now() - start;
            
            start = std::chrono::high_resolution_clock::now();
            cipher.decrypt(test_data, key->span(), nonce, tag);
            auto dec_time = std::chrono::high_resolution_clock::now() - start;
            
            std::cout << "  AES-256-GCM:\n";
            std::cout << "    Encrypt: " << std::chrono::duration_cast<std::chrono::nanoseconds>(enc_time).count() << " ns\n";
            std::cout << "    Decrypt: " << std::chrono::duration_cast<std::chrono::nanoseconds>(dec_time).count() << " ns\n";
        }
        
        // ChaCha20-Poly1305
        {
            psyfer::chacha20_poly1305 cipher;
            std::vector<std::byte> test_data = data;
            std::array<std::byte, 12> nonce;
            std::array<std::byte, 16> tag;
            secure_random::generate(nonce);
            
            auto start = std::chrono::high_resolution_clock::now();
            cipher.encrypt(test_data, key->span(), nonce, tag);
            auto enc_time = std::chrono::high_resolution_clock::now() - start;
            
            start = std::chrono::high_resolution_clock::now();
            cipher.decrypt(test_data, key->span(), nonce, tag);
            auto dec_time = std::chrono::high_resolution_clock::now() - start;
            
            std::cout << "  ChaCha20-Poly1305:\n";
            std::cout << "    Encrypt: " << std::chrono::duration_cast<std::chrono::nanoseconds>(enc_time).count() << " ns\n";
            std::cout << "    Decrypt: " << std::chrono::duration_cast<std::chrono::nanoseconds>(dec_time).count() << " ns\n";
        }
    }
}

int main() {
    std::cout << "Psyfer Authenticated Encryption Examples\n";
    std::cout << "======================================\n";
    
    try {
        example_aes_gcm_basic();
        example_aead_with_aad();
        example_chacha20_poly1305();
        example_nonce_management();
        example_tag_verification();
        example_streaming_aead();
        example_cipher_comparison();
        
        std::cout << "\n✅ All authenticated encryption examples completed successfully!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}