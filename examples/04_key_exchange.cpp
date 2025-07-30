/**
 * @file 04_key_exchange.cpp
 * @brief X25519 key exchange examples
 * 
 * This example demonstrates:
 * - Generating X25519 key pairs
 * - Computing shared secrets
 * - Using shared secrets for encryption
 * - Multiple party key exchange
 * - Key validation
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <iomanip>

using namespace psyfer;

/**
 * @brief Helper to print keys in hex
 */
void print_key(const std::string& label, std::span<const std::byte, 32> key) {
    std::cout << label << ": ";
    for (size_t i = 0; i < 8; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(static_cast<uint8_t>(key[i]));
    }
    std::cout << "..." << std::dec << "\n";
}

/**
 * @brief Example 1: Basic key exchange between two parties
 */
void example_basic_key_exchange() {
    std::cout << "\n=== Example 1: Basic X25519 Key Exchange ===\n";
    
    // Alice generates her key pair
    auto alice_keypair = crypto::x25519::key_pair::generate();
    if (!alice_keypair) {
        std::cerr << "Failed to generate Alice's key pair\n";
        return;
    }
    
    // Bob generates his key pair
    auto bob_keypair = crypto::x25519::key_pair::generate();
    if (!bob_keypair) {
        std::cerr << "Failed to generate Bob's key pair\n";
        return;
    }
    
    std::cout << "Alice's keys:\n";
    print_key("  Private", alice_keypair->private_key);
    print_key("  Public", alice_keypair->public_key);
    
    std::cout << "\nBob's keys:\n";
    print_key("  Private", bob_keypair->private_key);
    print_key("  Public", bob_keypair->public_key);
    
    // Alice computes shared secret using Bob's public key
    std::array<std::byte, 32> alice_shared;
    auto err = alice_keypair->compute_shared_secret(bob_keypair->public_key, alice_shared);
    if (err) {
        std::cerr << "Alice failed to compute shared secret\n";
        return;
    }
    
    // Bob computes shared secret using Alice's public key
    std::array<std::byte, 32> bob_shared;
    err = bob_keypair->compute_shared_secret(alice_keypair->public_key, bob_shared);
    if (err) {
        std::cerr << "Bob failed to compute shared secret\n";
        return;
    }
    
    std::cout << "\nShared secrets:\n";
    print_key("  Alice computed", alice_shared);
    print_key("  Bob computed", bob_shared);
    
    // Verify they match
    bool match = (alice_shared == bob_shared);
    std::cout << "\nShared secrets match: " << (match ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 2: Using shared secret for encryption
 */
void example_shared_secret_encryption() {
    std::cout << "\n=== Example 2: Encryption with Shared Secret ===\n";
    
    // Generate key pairs
    auto alice_kp = crypto::x25519::key_pair::generate();
    auto bob_kp = crypto::x25519::key_pair::generate();
    if (!alice_kp || !bob_kp) return;
    
    // Compute shared secret
    std::array<std::byte, 32> shared_secret;
    auto err = alice_kp->compute_shared_secret(bob_kp->public_key, shared_secret);
    if (err) return;
    
    // Derive encryption key from shared secret using HKDF
    std::array<std::byte, 32> enc_key;
    err = kdf::hkdf::derive_sha256(
        shared_secret,
        std::span<const std::byte>{}, // No salt
        std::as_bytes(std::span("encryption-key")),
        enc_key
    );
    if (err) {
        std::cerr << "Key derivation failed\n";
        return;
    }
    
    print_key("Shared secret", shared_secret);
    print_key("Derived encryption key", enc_key);
    
    // Alice encrypts a message for Bob
    std::string message = "Meet me at the secret location at midnight";
    std::vector<std::byte> plaintext(
        reinterpret_cast<const std::byte*>(message.data()),
        reinterpret_cast<const std::byte*>(message.data() + message.size())
    );
    
    std::array<std::byte, 12> nonce;
    utils::secure_random::generate(nonce);
    std::array<std::byte, 16> tag;
    
    crypto::aes256_gcm cipher;
    err = cipher.encrypt(plaintext, enc_key, nonce, tag);
    if (err) {
        std::cerr << "Encryption failed\n";
        return;
    }
    
    std::cout << "\nAlice encrypts: \"" << message << "\"\n";
    std::cout << "Ciphertext size: " << plaintext.size() << " bytes\n";
    
    // Bob decrypts using the same derived key
    err = cipher.decrypt(plaintext, enc_key, nonce, tag);
    if (err) {
        std::cerr << "Decryption failed\n";
        return;
    }
    
    std::string decrypted(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    std::cout << "Bob decrypts: \"" << decrypted << "\"\n";
    std::cout << "Decryption: " << (decrypted == message ? "✅ SUCCESS" : "❌ FAILED") << "\n";
}

/**
 * @brief Example 3: Multiple key exchanges (group scenario)
 */
void example_group_key_exchange() {
    std::cout << "\n=== Example 3: Multiple Party Key Exchange ===\n";
    
    // Create multiple participants
    struct Participant {
        std::string name;
        crypto::x25519::key_pair keypair;
    };
    
    std::vector<Participant> participants;
    std::vector<std::string> names = {"Alice", "Bob", "Charlie", "Diana"};
    
    // Generate key pairs for all participants
    for (const auto& name : names) {
        auto kp = crypto::x25519::key_pair::generate();
        if (!kp) {
            std::cerr << "Failed to generate key pair for " << name << "\n";
            return;
        }
        participants.push_back({name, std::move(*kp)});
    }
    
    // Display public keys
    std::cout << "Participants and their public keys:\n";
    for (const auto& p : participants) {
        std::cout << "  " << p.name << ": ";
        for (size_t i = 0; i < 8; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(static_cast<uint8_t>(p.keypair.public_key[i]));
        }
        std::cout << "...\n";
    }
    
    // Compute pairwise shared secrets
    std::cout << "\nPairwise shared secrets:\n";
    for (size_t i = 0; i < participants.size(); ++i) {
        for (size_t j = i + 1; j < participants.size(); ++j) {
            std::array<std::byte, 32> shared;
            participants[i].keypair.compute_shared_secret(
                participants[j].keypair.public_key, shared
            );
            
            std::cout << "  " << participants[i].name << " <-> " 
                      << participants[j].name << ": ";
            for (size_t k = 0; k < 6; ++k) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(static_cast<uint8_t>(shared[k]));
            }
            std::cout << "...\n";
        }
    }
    std::cout << std::dec;
}

/**
 * @brief Example 4: Performance benchmarks
 */
void example_performance() {
    std::cout << "\n=== Example 4: X25519 Performance ===\n";
    
    const int iterations = 1000;
    
    // Benchmark key generation
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto kp = crypto::x25519::key_pair::generate();
        if (!kp) break;
    }
    
    auto keygen_time = std::chrono::high_resolution_clock::now() - start;
    
    // Benchmark shared secret computation
    auto alice_kp = crypto::x25519::key_pair::generate();
    auto bob_kp = crypto::x25519::key_pair::generate();
    if (!alice_kp || !bob_kp) return;
    
    std::array<std::byte, 32> shared;
    
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        alice_kp->compute_shared_secret(bob_kp->public_key, shared);
    }
    
    auto exchange_time = std::chrono::high_resolution_clock::now() - start;
    
    // Calculate operations per second
    double keygen_per_sec = iterations / 
        (std::chrono::duration<double>(keygen_time).count());
    double exchange_per_sec = iterations / 
        (std::chrono::duration<double>(exchange_time).count());
    
    std::cout << "Operations (" << iterations << " iterations):\n";
    std::cout << "  Key generation:  " << std::fixed << std::setprecision(0)
              << keygen_per_sec << " ops/sec\n";
    std::cout << "  Key exchange:    " << exchange_per_sec << " ops/sec\n";
    std::cout << "  Avg time per keygen:   " << std::setprecision(3)
              << (1000.0 / keygen_per_sec) << " ms\n";
    std::cout << "  Avg time per exchange: " 
              << (1000.0 / exchange_per_sec) << " ms\n";
}

/**
 * @brief Example 5: Key validation and edge cases
 */
void example_key_validation() {
    std::cout << "\n=== Example 5: Key Validation ===\n";
    
    // Test with all-zero private key (should be rejected or clamped)
    std::array<std::byte, 32> zero_key{};
    std::array<std::byte, 32> public_key;
    
    auto err = crypto::x25519::derive_public_key(zero_key, public_key);
    
    std::cout << "All-zero private key:\n";
    if (err) {
        std::cout << "  Derivation: ❌ REJECTED (good)\n";
    } else {
        std::cout << "  Derivation: ✅ ACCEPTED (clamped)\n";
        print_key("  Public key", public_key);
    }
    
    // Test with maximum private key
    std::array<std::byte, 32> max_key;
    std::fill(max_key.begin(), max_key.end(), std::byte{0xFF});
    
    err = crypto::x25519::derive_public_key(max_key, public_key);
    
    std::cout << "\nAll-0xFF private key:\n";
    if (err) {
        std::cout << "  Derivation: ❌ REJECTED\n";
    } else {
        std::cout << "  Derivation: ✅ ACCEPTED\n";
        print_key("  Public key", public_key);
    }
    
    // Test proper random key
    std::array<std::byte, 32> random_key;
    utils::secure_random::generate(random_key);
    
    err = crypto::x25519::derive_public_key(random_key, public_key);
    
    std::cout << "\nRandom private key:\n";
    if (err) {
        std::cout << "  Derivation: ❌ FAILED\n";
    } else {
        std::cout << "  Derivation: ✅ SUCCESS\n";
        print_key("  Private", random_key);
        print_key("  Public", public_key);
    }
}

/**
 * @brief Example 6: Forward secrecy demonstration
 */
void example_forward_secrecy() {
    std::cout << "\n=== Example 6: Forward Secrecy ===\n";
    
    // Alice has a long-term key pair
    auto alice_long_term = crypto::x25519::key_pair::generate();
    if (!alice_long_term) return;
    
    std::cout << "Alice's long-term public key:\n";
    print_key("  ", alice_long_term->public_key);
    
    // For each session, generate ephemeral keys
    std::cout << "\nSession keys and shared secrets:\n";
    
    for (int session = 1; session <= 3; ++session) {
        // Bob generates ephemeral key for this session
        auto bob_ephemeral = crypto::x25519::key_pair::generate();
        if (!bob_ephemeral) continue;
        
        // Compute session shared secret
        std::array<std::byte, 32> session_secret;
        bob_ephemeral->compute_shared_secret(alice_long_term->public_key, session_secret);
        
        std::cout << "Session " << session << ":\n";
        print_key("  Bob's ephemeral public", bob_ephemeral->public_key);
        print_key("  Shared secret", session_secret);
        
        // Ephemeral key is discarded after use
    }
    
    std::cout << "\nEach session has a unique shared secret.\n";
    std::cout << "Compromising one session doesn't affect others.\n";
}

int main() {
    std::cout << "Psyfer X25519 Key Exchange Examples\n";
    std::cout << "===================================\n";
    
    try {
        example_basic_key_exchange();
        example_shared_secret_encryption();
        example_group_key_exchange();
        example_performance();
        example_key_validation();
        example_forward_secrecy();
        
        std::cout << "\n✅ All key exchange examples completed successfully!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}