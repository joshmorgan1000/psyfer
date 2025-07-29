#pragma once
/**
 * @file ed25519.hpp
 * @brief Ed25519 digital signature algorithm
 */

#include <psyfer.hpp>
#include <array>
#include <cstddef>
#include <cstdint>

namespace psyfer::crypto {

/**
 * @brief Ed25519 digital signature algorithm
 * 
 * Ed25519 is a public-key signature system with:
 * - 32-byte private keys
 * - 32-byte public keys
 * - 64-byte signatures
 * - ~128-bit security level
 * 
 * Uses hardware acceleration when available.
 */
class ed25519 {
public:
    static constexpr size_t PRIVATE_KEY_SIZE = 32;
    static constexpr size_t PUBLIC_KEY_SIZE = 32;
    static constexpr size_t SIGNATURE_SIZE = 64;
    static constexpr size_t SEED_SIZE = 32;
    
    /**
     * @brief Ed25519 key pair
     */
    struct key_pair {
        std::array<std::byte, PRIVATE_KEY_SIZE> private_key;
        std::array<std::byte, PUBLIC_KEY_SIZE> public_key;
    };
    
    /**
     * @brief Generate a new Ed25519 key pair
     * @return Key pair or error
     */
    [[nodiscard]] static result<key_pair> generate_key_pair() noexcept;
    
    /**
     * @brief Generate key pair from seed
     * @param seed 32-byte seed
     * @return Key pair or error
     */
    [[nodiscard]] static result<key_pair> key_pair_from_seed(
        std::span<const std::byte, SEED_SIZE> seed
    ) noexcept;
    
    /**
     * @brief Extract public key from private key
     * @param private_key The private key
     * @param public_key Output buffer for public key
     */
    static void public_key_from_private(
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    
    /**
     * @brief Sign a message
     * @param message Message to sign
     * @param private_key Private key to sign with
     * @param signature Output buffer for signature (64 bytes)
     * @return Error code on failure
     */
    [[nodiscard]] static std::error_code sign(
        std::span<const std::byte> message,
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, SIGNATURE_SIZE> signature
    ) noexcept;
    
    /**
     * @brief Verify a signature
     * @param message Original message
     * @param signature Signature to verify
     * @param public_key Public key to verify with
     * @return true if signature is valid, false otherwise
     */
    [[nodiscard]] static bool verify(
        std::span<const std::byte> message,
        std::span<const std::byte, SIGNATURE_SIZE> signature,
        std::span<const std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    
    /**
     * @brief Sign with detached signature (more efficient for large messages)
     * 
     * This computes the signature without including the message in the output.
     * Use this for large messages to avoid copying.
     */
    [[nodiscard]] static std::error_code sign_detached(
        std::span<const std::byte> message,
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, SIGNATURE_SIZE> signature
    ) noexcept;
    
    /**
     * @brief Verify detached signature
     */
    [[nodiscard]] static bool verify_detached(
        std::span<const std::byte> message,
        std::span<const std::byte, SIGNATURE_SIZE> signature,
        std::span<const std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    
    /**
     * @brief Check if hardware acceleration is available
     */
    [[nodiscard]] static bool hardware_accelerated() noexcept;
};

} // namespace psyfer::crypto