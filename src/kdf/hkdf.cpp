/**
 * @file hkdf.cpp
 * @brief HKDF implementation using CommonCrypto on Apple platforms
 */

#include <psyfer.hpp>
#include <cstring>

#ifdef __APPLE__
#include <CommonCrypto/CommonKeyDerivation.h>
#endif

namespace psyfer {

// HKDF-Extract implementations
void hextract_sha256(
    std::span<const std::byte> salt,
    std::span<const std::byte> ikm,
    std::span<std::byte, 32> prk
) noexcept {
    // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
    // If salt is empty, use string of zeros
    if (salt.empty()) {
        std::array<std::byte, 32> zero_salt{};
        hmac_sha256_algorithm::hmac(zero_salt, ikm, prk);
    } else {
        hmac_sha256_algorithm::hmac(salt, ikm, prk);
    }
}

void hextract_sha512(
    std::span<const std::byte> salt,
    std::span<const std::byte> ikm,
    std::span<std::byte, 64> prk
) noexcept {
    // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
    // If salt is empty, use string of zeros
    if (salt.empty()) {
        std::array<std::byte, 64> zero_salt{};
        hmac_sha512_algorithm::hmac(zero_salt, ikm, prk);
    } else {
        hmac_sha512_algorithm::hmac(salt, ikm, prk);
    }
}

// HKDF-Expand implementations
std::error_code hexpand_sha256(
    std::span<const std::byte, 32> prk,
    std::span<const std::byte> info,
    std::span<std::byte> okm
) noexcept {
    // Check output length
    if (okm.size() > 255 * 32) { // MAX_OUTPUT_SHA256
        return make_error_code(error_code::invalid_buffer_size);
    }
    
    if (okm.empty()) {
        return {};
    }
    
    // HKDF-Expand(PRK, info, L) implementation
    size_t hash_len = 32;
    size_t n = (okm.size() + hash_len - 1) / hash_len;  // Ceiling division
    size_t offset = 0;
    
    std::array<std::byte, 32> t;
    std::vector<std::byte> t_prev;
    
    for (size_t i = 1; i <= n; ++i) {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | counter)
        hmac_sha256_algorithm hmac(prk);
        
        // Add T(i-1) if not first iteration
        if (i > 1) {
            hmac.update(t_prev);
        }
        
        // Add info
        hmac.update(info);
        
        // Add counter (single byte)
        uint8_t counter = static_cast<uint8_t>(i);
        hmac.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(&counter), 1
        ));
        
        hmac.finalize(t);
        
        // Copy to output
        size_t to_copy = std::min(hash_len, okm.size() - offset);
        std::memcpy(okm.data() + offset, t.data(), to_copy);
        offset += to_copy;
        
        // Save T(i) for next iteration
        t_prev.assign(t.begin(), t.begin() + to_copy);
    }
    
    return {};
}

std::error_code hexpand_sha512(
    std::span<const std::byte, 64> prk,
    std::span<const std::byte> info,
    std::span<std::byte> okm
) noexcept {
    // Check output length
    if (okm.size() > 255 * 64) { // MAX_OUTPUT_SHA512
        return make_error_code(error_code::invalid_buffer_size);
    }
    
    if (okm.empty()) {
        return {};
    }
    
    // HKDF-Expand(PRK, info, L) implementation
    size_t hash_len = 64;
    size_t n = (okm.size() + hash_len - 1) / hash_len;  // Ceiling division
    size_t offset = 0;
    
    std::array<std::byte, 64> t;
    std::vector<std::byte> t_prev;
    
    for (size_t i = 1; i <= n; ++i) {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | counter)
        hmac_sha512_algorithm hmac(prk);
        
        // Add T(i-1) if not first iteration
        if (i > 1) {
            hmac.update(t_prev);
        }
        
        // Add info
        hmac.update(info);
        
        // Add counter (single byte)
        uint8_t counter = static_cast<uint8_t>(i);
        hmac.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(&counter), 1
        ));
        
        hmac.finalize(t);
        
        // Copy to output
        size_t to_copy = std::min(hash_len, okm.size() - offset);
        std::memcpy(okm.data() + offset, t.data(), to_copy);
        offset += to_copy;
        
        // Save T(i) for next iteration
        t_prev.assign(t.begin(), t.begin() + to_copy);
    }
    
    return {};
}

// Full HKDF implementations
std::error_code hkdf::derive_sha256(
    std::span<const std::byte> ikm,
    std::span<const std::byte> salt,
    std::span<const std::byte> info,
    std::span<std::byte> okm
) noexcept {
#ifdef __APPLE__
    // Use CommonCrypto's optimized implementation if available
    #ifdef CCPBKDF2_SALT_MAX_LENGTH  // Check if CCKeyDerivationPBKDF is available
    // Note: CommonCrypto doesn't have direct HKDF support in public API
    // Fall back to our implementation
    #endif
#endif
    
    // Extract step
    std::array<std::byte, 32> prk;
    hextract_sha256(salt, ikm, prk);
    
    // Expand step
    return hexpand_sha256(prk, info, okm);
}

std::error_code hkdf::derive_sha512(
    std::span<const std::byte> ikm,
    std::span<const std::byte> salt,
    std::span<const std::byte> info,
    std::span<std::byte> okm
) noexcept {
    // Extract step
    std::array<std::byte, 64> prk;
    hextract_sha512(salt, ikm, prk);
    
    // Expand step
    return hexpand_sha512(prk, info, okm);
}

} // namespace psyfer
