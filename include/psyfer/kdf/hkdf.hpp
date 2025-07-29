#pragma once
/**
 * @file hkdf.hpp
 * @brief HKDF (HMAC-based Key Derivation Function) implementation
 */

#include <psyfer.hpp>
#include <psyfer/hash/sha.hpp>
#include <psyfer/utils/secure.hpp>

namespace psyfer::kdf {

/**
 * @brief HKDF implementation as per RFC 5869
 * 
 * HKDF is a simple key derivation function based on HMAC.
 * It follows the "extract-then-expand" paradigm.
 */
class hkdf {
public:
    /**
     * @brief HKDF with SHA-256
     * 
     * @param ikm Input keying material
     * @param salt Optional salt value (can be empty)
     * @param info Optional context and application specific information
     * @param okm Output keying material buffer
     * @return Error code on failure
     */
    [[nodiscard]] static std::error_code derive_sha256(
        std::span<const std::byte> ikm,
        std::span<const std::byte> salt,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;
    
    /**
     * @brief HKDF with SHA-512
     * 
     * @param ikm Input keying material
     * @param salt Optional salt value (can be empty)
     * @param info Optional context and application specific information
     * @param okm Output keying material buffer
     * @return Error code on failure
     */
    [[nodiscard]] static std::error_code derive_sha512(
        std::span<const std::byte> ikm,
        std::span<const std::byte> salt,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;
    
    /**
     * @brief HKDF-Extract with SHA-256
     * 
     * Extract a fixed-length pseudorandom key from input keying material.
     * 
     * @param salt Optional salt value (can be empty)
     * @param ikm Input keying material
     * @param prk Output pseudorandom key (32 bytes for SHA-256)
     */
    static void extract_sha256(
        std::span<const std::byte> salt,
        std::span<const std::byte> ikm,
        std::span<std::byte, 32> prk
    ) noexcept;
    
    /**
     * @brief HKDF-Extract with SHA-512
     * 
     * Extract a fixed-length pseudorandom key from input keying material.
     * 
     * @param salt Optional salt value (can be empty)
     * @param ikm Input keying material
     * @param prk Output pseudorandom key (64 bytes for SHA-512)
     */
    static void extract_sha512(
        std::span<const std::byte> salt,
        std::span<const std::byte> ikm,
        std::span<std::byte, 64> prk
    ) noexcept;
    
    /**
     * @brief HKDF-Expand with SHA-256
     * 
     * Expand a pseudorandom key to desired length.
     * 
     * @param prk Pseudorandom key from extract step (32 bytes)
     * @param info Optional context and application specific information
     * @param okm Output keying material buffer
     * @return Error code on failure (if output length > 255 * HashLen)
     */
    [[nodiscard]] static std::error_code expand_sha256(
        std::span<const std::byte, 32> prk,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;
    
    /**
     * @brief HKDF-Expand with SHA-512
     * 
     * Expand a pseudorandom key to desired length.
     * 
     * @param prk Pseudorandom key from extract step (64 bytes)
     * @param info Optional context and application specific information
     * @param okm Output keying material buffer
     * @return Error code on failure (if output length > 255 * HashLen)
     */
    [[nodiscard]] static std::error_code expand_sha512(
        std::span<const std::byte, 64> prk,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;

private:
    // Maximum output length for HKDF
    static constexpr size_t MAX_OUTPUT_SHA256 = 255 * 32;
    static constexpr size_t MAX_OUTPUT_SHA512 = 255 * 64;
};

} // namespace psyfer::kdf