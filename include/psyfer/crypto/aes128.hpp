#pragma once
/**
 * @file aes128.hpp
 * @brief AES-128 encryption implementation with hardware acceleration
 */

#include <psyfer.hpp>
#include <array>
#include <cstring>

namespace psyfer::crypto {

/**
 * @brief AES-128 block cipher implementation
 * 
 * This is a C++23 implementation of AES-128 that uses hardware
 * acceleration (AES-NI or CryptoKit) when available, falling back 
 * to software implementation otherwise.
 */
class aes128 {
public:
    static constexpr size_t BLOCK_SIZE = 16;  // 128 bits
    static constexpr size_t KEY_SIZE = 16;    // 128 bits
    static constexpr size_t ROUNDS = 10;      // AES-128 uses 10 rounds
    
    /**
     * @brief Construct AES-128 cipher with key
     * @param key 16-byte encryption key
     */
    explicit aes128(std::span<const std::byte, KEY_SIZE> key) noexcept;
    
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

// Platform-specific acceleration functions
#ifdef __APPLE__
/**
 * @brief Check if CommonCrypto is available
 */
bool aes128_commoncrypto_available() noexcept;

/**
 * @brief Encrypt a block using CommonCrypto
 */
void aes128_encrypt_block_cc(const uint8_t* key, uint8_t* block) noexcept;

/**
 * @brief Decrypt a block using CommonCrypto
 */
void aes128_decrypt_block_cc(const uint8_t* key, uint8_t* block) noexcept;
#endif

#if defined(__AES__) && (defined(__x86_64__) || defined(__i386__))
/**
 * @brief Encrypt a block using AES-NI
 */
void aes128_encrypt_block_ni(const uint8_t* round_keys, uint8_t* block) noexcept;

/**
 * @brief Decrypt a block using AES-NI
 */  
void aes128_decrypt_block_ni(const uint8_t* round_keys, uint8_t* block) noexcept;

/**
 * @brief Key expansion using AES-NI
 */
void aes128_key_expansion_ni(const uint8_t* key, uint8_t* round_keys) noexcept;
#endif

} // namespace psyfer::crypto