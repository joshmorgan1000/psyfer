#pragma once
/**
 * @file aes256.hpp
 * @brief AES-256 encryption implementation with GCM mode
 */

#include <psyfer.hpp>
#include <array>
#include <cstring>

namespace psyfer::crypto {

/**
 * @brief Check if AES-NI hardware acceleration is available
 */
[[nodiscard]] bool aes_ni_available() noexcept;

/**
 * @brief AES-256 block cipher implementation
 * 
 * This is a C++23 implementation of AES-256 that uses hardware
 * acceleration (AES-NI) when available, falling back to software
 * implementation otherwise.
 */
class aes256 {
public:
    static constexpr size_t BLOCK_SIZE = 16;  // 128 bits
    static constexpr size_t KEY_SIZE = 32;    // 256 bits
    static constexpr size_t ROUNDS = 14;      // AES-256 uses 14 rounds
    
    /**
     * @brief Construct AES-256 cipher with key
     * @param key 32-byte encryption key
     */
    explicit aes256(std::span<const std::byte, KEY_SIZE> key) noexcept;
    
    /**
     * @brief Encrypt a single block
     * @param block 16-byte block to encrypt (modified in-place)
     */
    void encrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept;
    
    /**
     * @brief Decrypt a single block
     * @param block 16-byte block to decrypt (modified in-place)
     */
    void decrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept;

private:
    // Round keys: (ROUNDS + 1) * BLOCK_SIZE bytes
    alignas(16) std::array<std::byte, (ROUNDS + 1) * BLOCK_SIZE> round_keys{};
    bool use_hw_acceleration = false;
    
    /**
     * @brief Perform key expansion
     */
    void key_expansion(std::span<const std::byte, KEY_SIZE> key) noexcept;
    
    /**
     * @brief Software implementation of block encryption
     */
    void encrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept;
    
    /**
     * @brief Software implementation of block decryption
     */
    void decrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept;
};

/**
 * @brief AES-256-GCM authenticated encryption
 * 
 * Galois/Counter Mode provides both confidentiality and authenticity.
 * This implementation follows NIST SP 800-38D.
 */
class aes256_gcm final : public encryption_algorithm {
public:
    static constexpr size_t KEY_SIZE = 32;    // 256 bits
    static constexpr size_t NONCE_SIZE = 12;  // 96 bits (recommended)
    static constexpr size_t TAG_SIZE = 16;    // 128 bits
    
    /**
     * @brief Construct AES-256-GCM cipher
     */
    aes256_gcm() noexcept = default;
    
    /**
     * @brief Get the key size (32 bytes)
     */
    [[nodiscard]] size_t key_size() const noexcept override { return KEY_SIZE; }
    
    /**
     * @brief Get the nonce size (12 bytes)
     */
    [[nodiscard]] size_t nonce_size() const noexcept override { return NONCE_SIZE; }
    
    /**
     * @brief Get the tag size (16 bytes)
     */
    [[nodiscard]] size_t tag_size() const noexcept override { return TAG_SIZE; }
    
    /**
     * @brief Encrypt data in-place with AES-256-GCM
     */
    [[nodiscard]] std::error_code encrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept override;
    
    /**
     * @brief Decrypt data in-place with AES-256-GCM
     */
    [[nodiscard]] std::error_code decrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<const std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept override;
    
    /**
     * @brief One-shot encryption
     */
    static std::error_code encrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
    
    /**
     * @brief One-shot decryption
     */
    static std::error_code decrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<const std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;

private:
    /**
     * @brief GCM multiplication in GF(2^128)
     */
    static void ghash(
        std::span<std::byte, 16> output,
        std::span<const std::byte, 16> h,
        std::span<const std::byte> data
    ) noexcept;
    
    /**
     * @brief Increment counter block
     */
    static void increment_counter(std::span<std::byte, 16> counter) noexcept;
};

} // namespace psyfer::crypto