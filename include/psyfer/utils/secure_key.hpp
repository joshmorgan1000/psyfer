#pragma once
/**
 * @file secure_key.hpp
 * @brief Convenient secure key management class
 */

#include <psyfer/utils/secure.hpp>
#include <chrono>
#include <optional>

namespace psyfer::utils {

/**
 * @brief Secure key management class
 * 
 * Provides a convenient wrapper around secure memory and random generation
 * for cryptographic keys. Features:
 * - Automatic secure memory management
 * - Key generation with various algorithms
 * - Key derivation functions
 * - Serialization/deserialization with protection
 * - Automatic key rotation support
 */
template<size_t KeySize>
class secure_key {
public:
    static constexpr size_t size = KeySize;
    using key_type = secure_buffer<KeySize>;
    
    /**
     * @brief Default constructor (creates empty key)
     */
    secure_key() noexcept = default;
    
    /**
     * @brief Generate a new random key
     */
    [[nodiscard]] static result<secure_key> generate() noexcept {
        secure_key key;
        auto ec = secure_random::generate(key.key_.span());
        if (ec) {
            return std::unexpected(ec);
        }
        key.created_at_ = std::chrono::steady_clock::now();
        return key;
    }
    
    /**
     * @brief Create from existing key material
     * @param key_data The key data (must be exactly KeySize bytes)
     */
    [[nodiscard]] static secure_key from_bytes(std::span<const std::byte, KeySize> key_data) noexcept {
        secure_key key;
        key.key_.fill(key_data);
        key.created_at_ = std::chrono::steady_clock::now();
        return key;
    }
    
    /**
     * @brief Create from password using key derivation
     * @param password The password to derive from
     * @param salt Salt for key derivation (32 bytes recommended)
     * @param iterations Number of iterations (100000+ recommended)
     */
    [[nodiscard]] static result<secure_key> from_password(
        std::string_view password,
        std::span<const std::byte> salt,
        uint32_t iterations = 100000
    ) noexcept;
    
    /**
     * @brief Get the key data as a span
     */
    [[nodiscard]] std::span<const std::byte, KeySize> span() const noexcept {
        return key_.span();
    }
    
    /**
     * @brief Get raw pointer (use with caution)
     */
    [[nodiscard]] const std::byte* data() const noexcept {
        return key_.data();
    }
    
    /**
     * @brief Check if key is empty (all zeros)
     */
    [[nodiscard]] bool is_empty() const noexcept {
        for (auto b : key_.span()) {
            if (b != std::byte{0}) return false;
        }
        return true;
    }
    
    /**
     * @brief Get key age
     */
    [[nodiscard]] std::chrono::steady_clock::duration age() const noexcept {
        return std::chrono::steady_clock::now() - created_at_;
    }
    
    /**
     * @brief Check if key should be rotated based on age
     * @param max_age Maximum key age before rotation
     */
    [[nodiscard]] bool should_rotate(std::chrono::steady_clock::duration max_age) const noexcept {
        return age() > max_age;
    }
    
    /**
     * @brief Clear the key
     */
    void clear() noexcept {
        key_.clear();
        created_at_ = {};
    }
    
    /**
     * @brief Securely compare two keys
     */
    [[nodiscard]] bool operator==(const secure_key& other) const noexcept {
        return secure_compare(key_.data(), other.key_.data(), KeySize);
    }
    
    /**
     * @brief Export key with additional protection
     * @param protection_key Key to encrypt this key with
     * @return Encrypted key data
     */
    [[nodiscard]] result<secure_vector<std::byte>> export_protected(
        std::span<const std::byte, 32> protection_key
    ) const noexcept;
    
    /**
     * @brief Import protected key
     * @param encrypted_data The encrypted key data
     * @param protection_key Key to decrypt with
     */
    [[nodiscard]] static result<secure_key> import_protected(
        std::span<const std::byte> encrypted_data,
        std::span<const std::byte, 32> protection_key
    ) noexcept;

private:
    key_type key_;
    std::chrono::steady_clock::time_point created_at_;
};

/**
 * @brief Convenient type aliases for common key sizes
 */
using secure_key_128 = secure_key<16>;   // 128-bit keys
using secure_key_192 = secure_key<24>;   // 192-bit keys
using secure_key_256 = secure_key<32>;   // 256-bit keys
using secure_key_512 = secure_key<64>;   // 512-bit keys

/**
 * @brief AES-256 key type
 */
using aes256_key = secure_key<32>;

/**
 * @brief ChaCha20 key type
 */
using chacha20_key = secure_key<32>;

/**
 * @brief X25519 private key type
 */
using x25519_private_key = secure_key<32>;
using x25519_key = x25519_private_key;  // Alias for convenience

/**
 * @brief BLAKE3 key type
 */
using blake3_key = secure_key<32>;

} // namespace psyfer::utils