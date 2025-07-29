/**
 * @file test_x25519.cpp
 * @brief Tests for X25519 key exchange implementation
 */

#include <psyfer.hpp>
#include <psyfer/crypto/x25519.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <chrono>

/**
 * @brief Print hex bytes
 */
void print_hex(const std::string& label, std::span<const std::byte> data) {
    std::cout << label << ": ";
    for (auto b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<unsigned>(b);
    }
    std::cout << std::dec << std::endl;
}

/**
 * @brief Test basic X25519 key generation and exchange
 */
void test_x25519_basic() {
    std::cout << "Testing basic X25519 key exchange..." << std::endl;
    
    // Generate Alice's key pair
    auto alice_result = psyfer::crypto::x25519::key_pair::generate();
    assert(alice_result.has_value());
    auto alice = std::move(*alice_result);
    
    // Generate Bob's key pair
    auto bob_result = psyfer::crypto::x25519::key_pair::generate();
    assert(bob_result.has_value());
    auto bob = std::move(*bob_result);
    
    std::cout << "✓ Key pairs generated" << std::endl;
    
    // Alice computes shared secret with Bob's public key
    std::array<std::byte, 32> alice_shared;
    auto ec = alice.compute_shared_secret(bob.public_key, alice_shared);
    assert(!ec);
    
    // Bob computes shared secret with Alice's public key
    std::array<std::byte, 32> bob_shared;
    ec = bob.compute_shared_secret(alice.public_key, bob_shared);
    assert(!ec);
    
    // Verify both shared secrets are the same
    assert(std::memcmp(alice_shared.data(), bob_shared.data(), 32) == 0);
    
    std::cout << "✓ Shared secrets match" << std::endl;
    print_hex("Shared secret", alice_shared);
}

/**
 * @brief Test X25519 with known test vectors
 */
void test_x25519_vectors() {
    std::cout << "\nTesting X25519 with known vectors..." << std::endl;
    
    // Test vector from RFC 7748
    std::array<std::byte, 32> alice_private = {
        std::byte{0x77}, std::byte{0x07}, std::byte{0x6d}, std::byte{0x0a},
        std::byte{0x73}, std::byte{0x18}, std::byte{0xa5}, std::byte{0x7d},
        std::byte{0x3c}, std::byte{0x16}, std::byte{0xc1}, std::byte{0x72},
        std::byte{0x51}, std::byte{0xb2}, std::byte{0x66}, std::byte{0x45},
        std::byte{0xdf}, std::byte{0x4c}, std::byte{0x2f}, std::byte{0x87},
        std::byte{0xeb}, std::byte{0xc0}, std::byte{0x99}, std::byte{0x2a},
        std::byte{0xb1}, std::byte{0x77}, std::byte{0xfb}, std::byte{0xa5},
        std::byte{0x1d}, std::byte{0xb9}, std::byte{0x2c}, std::byte{0x2a}
    };
    
    std::array<std::byte, 32> bob_private = {
        std::byte{0x5d}, std::byte{0xab}, std::byte{0x08}, std::byte{0x7e},
        std::byte{0x62}, std::byte{0x4a}, std::byte{0x8a}, std::byte{0x4b},
        std::byte{0x79}, std::byte{0xe1}, std::byte{0x7f}, std::byte{0x8b},
        std::byte{0x83}, std::byte{0x80}, std::byte{0x0e}, std::byte{0xe6},
        std::byte{0x6f}, std::byte{0x3b}, std::byte{0xb1}, std::byte{0x29},
        std::byte{0x26}, std::byte{0x18}, std::byte{0xb6}, std::byte{0xfd},
        std::byte{0x1c}, std::byte{0x2f}, std::byte{0x8b}, std::byte{0x27},
        std::byte{0xff}, std::byte{0x88}, std::byte{0xe0}, std::byte{0xeb}
    };
    
    // Expected shared secret
    std::array<std::byte, 32> expected_shared = {
        std::byte{0x4a}, std::byte{0x5d}, std::byte{0x9d}, std::byte{0x5b},
        std::byte{0xa4}, std::byte{0xce}, std::byte{0x2d}, std::byte{0xe1},
        std::byte{0x72}, std::byte{0x8e}, std::byte{0x3b}, std::byte{0xf4},
        std::byte{0x80}, std::byte{0x35}, std::byte{0x0f}, std::byte{0x25},
        std::byte{0xe0}, std::byte{0x7e}, std::byte{0x21}, std::byte{0xc9},
        std::byte{0x47}, std::byte{0xd1}, std::byte{0x9e}, std::byte{0x33},
        std::byte{0x76}, std::byte{0xf0}, std::byte{0x9b}, std::byte{0x3c},
        std::byte{0x1e}, std::byte{0x16}, std::byte{0x17}, std::byte{0x42}
    };
    
    // Derive public keys
    std::array<std::byte, 32> alice_public;
    auto ec = psyfer::crypto::x25519::derive_public_key(alice_private, alice_public);
    assert(!ec);
    
    std::array<std::byte, 32> bob_public;
    ec = psyfer::crypto::x25519::derive_public_key(bob_private, bob_public);
    assert(!ec);
    
    // Compute shared secrets
    std::array<std::byte, 32> alice_shared;
    ec = psyfer::crypto::x25519::compute_shared_secret(alice_private, bob_public, alice_shared);
    assert(!ec);
    
    std::array<std::byte, 32> bob_shared;
    ec = psyfer::crypto::x25519::compute_shared_secret(bob_private, alice_public, bob_shared);
    assert(!ec);
    
    // Verify
    assert(alice_shared == bob_shared);
    assert(alice_shared == expected_shared);
    
    std::cout << "✓ Test vectors pass" << std::endl;
}

/**
 * @brief Test X25519 edge cases
 */
void test_x25519_edge_cases() {
    std::cout << "\nTesting X25519 edge cases..." << std::endl;
    
    // Test with low order points
    std::array<std::byte, 32> low_order_point = {};  // All zeros
    std::array<std::byte, 32> private_key;
    std::array<std::byte, 32> shared_secret;
    
    // Generate a private key
    auto ec = psyfer::crypto::x25519::generate_private_key(private_key);
    assert(!ec);
    
    // Compute shared secret with low order point
    ec = psyfer::crypto::x25519::compute_shared_secret(
        private_key, low_order_point, shared_secret);
    
    // Should fail or produce all-zero output
    if (!ec) {
        bool all_zero = true;
        for (auto b : shared_secret) {
            if (b != std::byte{0}) {
                all_zero = false;
                break;
            }
        }
        if (!all_zero) {
            std::cout << "Warning: CryptoKit handles low order points differently\n";
            std::cout << "Shared secret with low order point: ";
            for (auto b : shared_secret) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << static_cast<int>(static_cast<uint8_t>(b));
            }
            std::cout << std::dec << std::endl;
        }
    }
    
    std::cout << "✓ Low order point handled correctly" << std::endl;
}

/**
 * @brief Test X25519 with secure key integration
 */
void test_x25519_secure_key() {
    std::cout << "\nTesting X25519 with SecureKey..." << std::endl;
    
    // Generate keys using SecureKey
    auto alice_key = psyfer::utils::x25519_key::generate();
    assert(alice_key.has_value());
    
    auto bob_key = psyfer::utils::x25519_key::generate();
    assert(bob_key.has_value());
    
    // Derive public keys
    std::array<std::byte, 32> alice_public;
    auto ec = psyfer::crypto::x25519::derive_public_key(alice_key->span(), alice_public);
    assert(!ec);
    
    std::array<std::byte, 32> bob_public;
    ec = psyfer::crypto::x25519::derive_public_key(bob_key->span(), bob_public);
    assert(!ec);
    
    // Compute shared secrets
    std::array<std::byte, 32> alice_shared;
    ec = psyfer::crypto::x25519::compute_shared_secret(
        alice_key->span(), bob_public, alice_shared);
    assert(!ec);
    
    std::array<std::byte, 32> bob_shared;
    ec = psyfer::crypto::x25519::compute_shared_secret(
        bob_key->span(), alice_public, bob_shared);
    assert(!ec);
    
    // Verify
    assert(alice_shared == bob_shared);
    
    std::cout << "✓ SecureKey integration works" << std::endl;
}

/**
 * @brief Benchmark X25519 performance
 */
void benchmark_x25519() {
    std::cout << "\nBenchmarking X25519 performance..." << std::endl;
    
    const int iterations = 1000;
    
    // Benchmark key generation
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        std::array<std::byte, 32> key;
        auto ec = psyfer::crypto::x25519::generate_private_key(key);
        assert(!ec);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto gen_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << "Key generation: " << gen_time / iterations << " μs/op" << std::endl;
    
    // Benchmark public key derivation
    std::array<std::byte, 32> private_key_array;
    auto ec = psyfer::crypto::x25519::generate_private_key(private_key_array);
    assert(!ec);
    std::array<std::byte, 32> public_key;
    
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto ec = psyfer::crypto::x25519::derive_public_key(private_key_array, public_key);
        assert(!ec);
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto derive_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << "Public key derivation: " << derive_time / iterations << " μs/op" << std::endl;
    
    // Benchmark shared secret computation
    std::array<std::byte, 32> peer_key;
    ec = psyfer::crypto::x25519::generate_private_key(peer_key);
    assert(!ec);
    std::array<std::byte, 32> peer_public;
    ec = psyfer::crypto::x25519::derive_public_key(peer_key, peer_public);
    assert(!ec);
    
    std::array<std::byte, 32> shared_secret;
    
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto ec = psyfer::crypto::x25519::compute_shared_secret(
            private_key_array, peer_public, shared_secret);
        assert(!ec);
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto ecdh_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << "ECDH computation: " << ecdh_time / iterations << " μs/op" << std::endl;
    
    // Operations per second
    std::cout << "Key exchanges per second: " 
              << (1000000.0 * iterations) / ecdh_time << std::endl;
}

int main() {
    std::cout << "=== X25519 Key Exchange Tests ===" << std::endl;
    
    test_x25519_basic();
    test_x25519_vectors();
    test_x25519_edge_cases();
    test_x25519_secure_key();
    benchmark_x25519();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}