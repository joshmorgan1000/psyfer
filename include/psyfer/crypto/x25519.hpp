#pragma once
/**
 * @file x25519.hpp
 * @brief X25519 key exchange implementation (Curve25519 ECDH)
 * 
 * X25519 is a key agreement scheme using Curve25519. It allows two parties
 * to jointly agree on a shared secret using an elliptic curve Diffie-Hellman
 * (ECDH) variant.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <expected>
#include <vector>

namespace psyfer::crypto {

/**
 * @brief X25519 key exchange implementation
 * 
 * Implements the X25519 function as specified in RFC 7748.
 * X25519 is the Diffie-Hellman primitive built from Curve25519.
 * 
 * Security properties:
 * - 128-bit security level
 * - Resistant to timing attacks
 * - No need for point validation
 * - Simple and fast scalar multiplication
 * 
 * This implementation automatically uses CryptoKit hardware acceleration
 * when available on macOS 10.15+/iOS 13.0+, falling back to a portable
 * software implementation.
 */
class x25519 {
public:
    /**
     * @brief Key sizes for X25519
     */
    static constexpr size_t PRIVATE_KEY_SIZE = 32;
    static constexpr size_t PUBLIC_KEY_SIZE = 32;
    static constexpr size_t SHARED_SECRET_SIZE = 32;
    
    /**
     * @brief The basepoint for scalar multiplication
     */
    static constexpr std::array<uint8_t, 32> BASEPOINT = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    
    /**
     * @brief Generate a new X25519 private key
     * 
     * @param private_key Output buffer for private key (32 bytes)
     * @return Error code on failure
     */
    [[nodiscard]] static std::error_code generate_private_key(
        std::span<std::byte, PRIVATE_KEY_SIZE> private_key
    ) noexcept;
    
    /**
     * @brief Derive public key from private key
     * 
     * Computes: public_key = private_key * basepoint
     * 
     * @param private_key The private key (32 bytes)
     * @param public_key Output buffer for public key (32 bytes)
     * @return Error code on failure
     */
    [[nodiscard]] static std::error_code derive_public_key(
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    
    /**
     * @brief Compute shared secret
     * 
     * Computes: shared_secret = private_key * peer_public_key
     * 
     * @param private_key Our private key (32 bytes)
     * @param peer_public_key Peer's public key (32 bytes)
     * @param shared_secret Output buffer for shared secret (32 bytes)
     * @return Error code on failure
     */
    [[nodiscard]] static std::error_code compute_shared_secret(
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<const std::byte, PUBLIC_KEY_SIZE> peer_public_key,
        std::span<std::byte, SHARED_SECRET_SIZE> shared_secret
    ) noexcept;
    
    /**
     * @brief Key pair for X25519
     */
    struct key_pair {
        std::array<std::byte, PRIVATE_KEY_SIZE> private_key;
        std::array<std::byte, PUBLIC_KEY_SIZE> public_key;
        
        /**
         * @brief Generate a new key pair
         */
        [[nodiscard]] static std::expected<key_pair, std::error_code> generate() noexcept;
        
        /**
         * @brief Compute shared secret with peer
         */
        [[nodiscard]] std::error_code compute_shared_secret(
            std::span<const std::byte, PUBLIC_KEY_SIZE> peer_public_key,
            std::span<std::byte, SHARED_SECRET_SIZE> shared_secret
        ) const noexcept;
    };
    
    /**
     * @brief The core X25519 scalar multiplication function
     * 
     * @param out Output point (32 bytes)
     * @param scalar The scalar to multiply by (32 bytes)
     * @param point The point to multiply (32 bytes)
     */
    static void scalarmult(
        uint8_t* out,
        const uint8_t* scalar,
        const uint8_t* point
    ) noexcept;
    
private:
    
    /**
     * @brief Field element type (5 limbs of 51 bits each)
     */
    using fe = std::array<uint64_t, 5>;
    
    /**
     * @brief Field arithmetic operations
     */
    static void fe_frombytes(fe& h, const uint8_t* s) noexcept;
    static void fe_tobytes(uint8_t* s, const fe& h) noexcept;
    static void fe_add(fe& h, const fe& f, const fe& g) noexcept;
    static void fe_sub(fe& h, const fe& f, const fe& g) noexcept;
    static void fe_mul(fe& h, const fe& f, const fe& g) noexcept;
    static void fe_sq(fe& h, const fe& f) noexcept;
    static void fe_mul121666(fe& h, const fe& f) noexcept;
    static void fe_invert(fe& out, const fe& z) noexcept;
    static void fe_cswap(fe& f, fe& g, unsigned int b) noexcept;
};

} // namespace psyfer::crypto