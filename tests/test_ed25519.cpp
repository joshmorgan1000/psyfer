/**
 * @file test_ed25519.cpp
 * @brief Tests for Ed25519 implementation
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
 * @brief Test Ed25519 key generation
 */
void test_ed25519_key_generation() {
    std::cout << "Testing Ed25519 key generation..." << std::endl;
    
    // Generate random key pair
    auto kp_result = psyfer::crypto::ed25519::generate_key_pair();
    assert(kp_result.has_value());
    
    auto& kp = kp_result.value();
    print_hex("Private key", kp.private_key);
    print_hex("Public key", kp.public_key);
    
    // Generate another key pair
    auto kp2_result = psyfer::crypto::ed25519::generate_key_pair();
    assert(kp2_result.has_value());
    auto& kp2 = kp2_result.value();
    
    // Keys should be different
    assert(std::memcmp(kp.private_key.data(), kp2.private_key.data(), 32) != 0);
    assert(std::memcmp(kp.public_key.data(), kp2.public_key.data(), 32) != 0);
    
    std::cout << "✓ Key generation works" << std::endl;
}

/**
 * @brief Test Ed25519 deterministic key generation from seed
 */
void test_ed25519_key_from_seed() {
    std::cout << "\nTesting Ed25519 key generation from seed..." << std::endl;
    
    // Fixed seed
    std::array<std::byte, 32> seed;
    for (size_t i = 0; i < 32; ++i) {
        seed[i] = std::byte(i);
    }
    
    // Generate key pair from seed
    auto kp1 = psyfer::crypto::ed25519::key_pair_from_seed(seed);
    assert(kp1.has_value());
    
    // Generate again with same seed
    auto kp2 = psyfer::crypto::ed25519::key_pair_from_seed(seed);
    assert(kp2.has_value());
    
    // Should produce identical keys
    assert(std::memcmp(kp1->private_key.data(), kp2->private_key.data(), 32) == 0);
    assert(std::memcmp(kp1->public_key.data(), kp2->public_key.data(), 32) == 0);
    
    print_hex("Deterministic private key", kp1->private_key);
    print_hex("Deterministic public key", kp1->public_key);
    
    std::cout << "✓ Key from seed is deterministic" << std::endl;
}

/**
 * @brief Test Ed25519 public key derivation
 */
void test_ed25519_public_key_derivation() {
    std::cout << "\nTesting Ed25519 public key derivation..." << std::endl;
    
    auto kp = psyfer::crypto::ed25519::generate_key_pair();
    assert(kp.has_value());
    
    // Derive public key from private key
    std::array<std::byte, 32> derived_public;
    psyfer::crypto::ed25519::public_key_from_private(
        kp->private_key,
        derived_public
    );
    
    // Should match the public key in the pair
    assert(std::memcmp(derived_public.data(), kp->public_key.data(), 32) == 0);
    
    std::cout << "✓ Public key derivation works" << std::endl;
}

/**
 * @brief Test Ed25519 sign and verify
 */
void test_ed25519_sign_verify() {
    std::cout << "\nTesting Ed25519 sign and verify..." << std::endl;
    
    // Generate key pair
    auto kp = psyfer::crypto::ed25519::generate_key_pair();
    assert(kp.has_value());
    
    // Test message
    const char* msg = "Hello, Ed25519!";
    std::span<const std::byte> message(
        reinterpret_cast<const std::byte*>(msg),
        strlen(msg)
    );
    
    // Sign message
    std::array<std::byte, 64> signature;
    auto ec = psyfer::crypto::ed25519::sign(
        message,
        kp->private_key,
        signature
    );
    assert(!ec);
    print_hex("Signature", signature);
    
    // Verify signature
    bool valid = psyfer::crypto::ed25519::verify(
        message,
        signature,
        kp->public_key
    );
    assert(valid);
    std::cout << "✓ Valid signature verified" << std::endl;
    
    // Verify with wrong message
    const char* wrong_msg = "Hello, Ed25519?";
    std::span<const std::byte> wrong_message(
        reinterpret_cast<const std::byte*>(wrong_msg),
        strlen(wrong_msg)
    );
    
    valid = psyfer::crypto::ed25519::verify(
        wrong_message,
        signature,
        kp->public_key
    );
    assert(!valid);
    std::cout << "✓ Invalid message rejected" << std::endl;
    
    // Verify with wrong public key
    auto kp2 = psyfer::crypto::ed25519::generate_key_pair();
    assert(kp2.has_value());
    
    valid = psyfer::crypto::ed25519::verify(
        message,
        signature,
        kp2->public_key
    );
    assert(!valid);
    std::cout << "✓ Wrong public key rejected" << std::endl;
    
    // Corrupt signature
    signature[0] ^= std::byte{1};
    valid = psyfer::crypto::ed25519::verify(
        message,
        signature,
        kp->public_key
    );
    assert(!valid);
    std::cout << "✓ Corrupted signature rejected" << std::endl;
}

/**
 * @brief Test Ed25519 with various message sizes
 */
void test_ed25519_message_sizes() {
    std::cout << "\nTesting Ed25519 with various message sizes..." << std::endl;
    
    auto kp = psyfer::crypto::ed25519::generate_key_pair();
    assert(kp.has_value());
    
    std::vector<size_t> sizes = {0, 1, 32, 64, 128, 1024, 4096};
    
    for (size_t size : sizes) {
        std::vector<std::byte> message(size);
        for (size_t i = 0; i < size; ++i) {
            message[i] = std::byte(i & 0xff);
        }
        
        std::array<std::byte, 64> signature;
        auto ec = psyfer::crypto::ed25519::sign_detached(
            message,
            kp->private_key,
            signature
        );
        assert(!ec);
        
        bool valid = psyfer::crypto::ed25519::verify_detached(
            message,
            signature,
            kp->public_key
        );
        assert(valid);
        
        std::cout << "✓ Size " << size << " works" << std::endl;
    }
}

/**
 * @brief Test hardware acceleration detection
 */
void test_ed25519_hardware() {
    std::cout << "\nTesting Ed25519 hardware acceleration..." << std::endl;
    
    bool hw_accel = psyfer::crypto::ed25519::hardware_accelerated();
    std::cout << "Hardware acceleration: " << (hw_accel ? "YES" : "NO") << std::endl;
    
    // Note: Currently Ed25519 is not hardware accelerated on most platforms
    std::cout << "✓ Hardware detection works" << std::endl;
}

int main() {
    std::cout << "=== Ed25519 Tests ===" << std::endl;
    std::cout << "\nNOTE: This is a placeholder implementation for testing the interface." << std::endl;
    std::cout << "For production use, integrate a proper Ed25519 implementation." << std::endl;
    std::cout << std::endl;
    
    test_ed25519_key_generation();
    test_ed25519_key_from_seed();
    test_ed25519_public_key_derivation();
    test_ed25519_sign_verify();
    test_ed25519_message_sizes();
    test_ed25519_hardware();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}