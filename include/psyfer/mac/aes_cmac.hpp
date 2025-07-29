#pragma once
/**
 * @file aes_cmac.hpp
 * @brief AES-CMAC (Cipher-based Message Authentication Code) implementation
 * 
 * CMAC is a block cipher-based message authentication code algorithm.
 * It provides stronger assurance of data integrity than a checksum or CRC.
 * This implementation follows NIST SP 800-38B.
 */

#include <psyfer/crypto/aes256.hpp>
#include <array>
#include <cstring>
#include <span>
#include <memory>

namespace psyfer::mac {

/**
 * @brief AES-CMAC base template
 * 
 * @tparam KeySize The AES key size in bytes (16 for AES-128, 32 for AES-256)
 */
template<size_t KeySize>
class aes_cmac {
public:
    static constexpr size_t KEY_SIZE = KeySize;
    static constexpr size_t MAC_SIZE = 16;  // Always 128 bits regardless of key size
    static constexpr size_t BLOCK_SIZE = 16;
    
    /**
     * @brief Construct AES-CMAC with key
     * @param key The AES key
     */
    explicit aes_cmac(std::span<const std::byte, KEY_SIZE> key) noexcept;
    
    /**
     * @brief Destructor
     */
    ~aes_cmac() noexcept;
    
    /**
     * @brief Update the MAC with more data
     * @param data Data to process
     */
    void update(std::span<const std::byte> data) noexcept;
    
    /**
     * @brief Finalize and get the MAC value
     * @param mac Output buffer for MAC (16 bytes)
     */
    void finalize(std::span<std::byte, MAC_SIZE> mac) noexcept;
    
    /**
     * @brief Reset to initial state (keeps the key)
     */
    void reset() noexcept;
    
    /**
     * @brief One-shot MAC computation
     * @param data Data to authenticate
     * @param key The AES key
     * @param mac Output buffer for MAC
     */
    static void compute(
        std::span<const std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<std::byte, MAC_SIZE> mac
    ) noexcept;
    
    /**
     * @brief Verify a MAC
     * @param data Data to verify
     * @param key The AES key
     * @param mac MAC to verify against
     * @return true if MAC is valid
     */
    [[nodiscard]] static bool verify(
        std::span<const std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, MAC_SIZE> mac
    ) noexcept;

private:
    // Internal AES cipher - implementation detail
    struct cipher_impl;
    std::unique_ptr<cipher_impl> cipher;
    
    // CMAC state
    alignas(16) std::array<std::byte, BLOCK_SIZE> k1{};  // First subkey
    alignas(16) std::array<std::byte, BLOCK_SIZE> k2{};  // Second subkey
    alignas(16) std::array<std::byte, BLOCK_SIZE> state{};  // Current state
    alignas(16) std::array<std::byte, BLOCK_SIZE> buffer{};  // Partial block buffer
    size_t buffer_pos = 0;
    
    /**
     * @brief Generate CMAC subkeys K1 and K2
     */
    void generate_subkeys() noexcept;
    
    /**
     * @brief Process a complete block
     */
    void process_block(std::span<const std::byte, BLOCK_SIZE> block) noexcept;
    
    /**
     * @brief Left shift for subkey generation
     */
    static void left_shift_one(std::span<std::byte, BLOCK_SIZE> data) noexcept;
};

/**
 * @brief AES-CMAC-128 (uses AES-128)
 */
using aes_cmac_128 = aes_cmac<16>;

/**
 * @brief AES-CMAC-256 (uses AES-256)
 */
using aes_cmac_256 = aes_cmac<32>;

// Convenience aliases
using cmac128 = aes_cmac_128;
using cmac256 = aes_cmac_256;

} // namespace psyfer::mac