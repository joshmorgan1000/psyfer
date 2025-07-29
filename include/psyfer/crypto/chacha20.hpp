#pragma once
/**
 * @file chacha20.hpp
 * @brief ChaCha20 stream cipher and ChaCha20-Poly1305 AEAD
 */

#include <psyfer.hpp>

namespace psyfer::crypto {

/**
 * @brief ChaCha20 stream cipher implementation
 * 
 * ChaCha20 is a high-speed stream cipher designed by Daniel J. Bernstein.
 * It's an improved variant of Salsa20, providing better diffusion.
 * 
 * Features:
 * - 256-bit keys
 * - 96-bit nonces (12 bytes)
 * - 32-bit counter (supporting up to 256 GB per nonce)
 * - Constant-time operations
 * - SIMD-optimized where possible
 */
class chacha20 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t BLOCK_SIZE = 64;
    
    /**
     * @brief ChaCha20 quarter round operation
     */
    static void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept;
    
    /**
     * @brief Generate a ChaCha20 keystream block
     * @param key The 256-bit key
     * @param nonce The 96-bit nonce
     * @param counter The block counter
     * @param output Output buffer for keystream (64 bytes)
     */
    static void generate_block(
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        uint32_t counter,
        std::span<std::byte, BLOCK_SIZE> output
    ) noexcept;
    
    /**
     * @brief Encrypt/decrypt data with ChaCha20
     * @param data Data to encrypt/decrypt (modified in-place)
     * @param key The 256-bit key
     * @param nonce The 96-bit nonce
     * @param counter Initial counter value (default: 0)
     */
    static void crypt(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        uint32_t counter = 0
    ) noexcept;
    
private:
    /**
     * @brief Rotate left operation
     */
    [[nodiscard]] static constexpr uint32_t rotl(uint32_t x, int n) noexcept {
        return (x << n) | (x >> (32 - n));
    }
};

/**
 * @brief Poly1305 MAC implementation
 * 
 * Poly1305 is a fast message authentication code designed by Daniel J. Bernstein.
 * It produces a 16-byte tag and is designed to be used with a cipher like ChaCha20.
 */
class poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t TAG_SIZE = 16;
    
    poly1305() noexcept = default;
    
    /**
     * @brief Initialize with a 256-bit key
     * @param key The one-time key (must be unique per message)
     */
    void init(std::span<const std::byte, KEY_SIZE> key) noexcept;
    
    /**
     * @brief Update with more data
     * @param data Data to authenticate
     */
    void update(std::span<const std::byte> data) noexcept;
    
    /**
     * @brief Finalize and get the tag
     * @param tag Output buffer for tag (16 bytes)
     */
    void finalize(std::span<std::byte, TAG_SIZE> tag) noexcept;
    
    /**
     * @brief One-shot authentication
     * @param data Data to authenticate
     * @param key The one-time key
     * @param tag Output buffer for tag
     */
    static void auth(
        std::span<const std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<std::byte, TAG_SIZE> tag
    ) noexcept;
    
private:
    // Poly1305 internal state
    uint32_t r_[5] = {0};  // Clamped part of key
    uint32_t h_[5] = {0};  // Accumulator
    uint32_t pad_[4] = {0}; // Encrypted nonce
    size_t leftover_ = 0;
    uint8_t buffer_[16] = {0};
    bool finalized_ = false;
    
    void process_block(const uint8_t* block, bool final = false) noexcept;
};

/**
 * @brief ChaCha20-Poly1305 AEAD implementation
 * 
 * Combines ChaCha20 stream cipher with Poly1305 MAC for authenticated
 * encryption with associated data (AEAD). This is the IETF variant
 * as specified in RFC 8439.
 */
class chacha20_poly1305 final : public encryption_algorithm {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    
    /**
     * @brief Get the key size required for this algorithm
     */
    [[nodiscard]] size_t key_size() const noexcept override { return KEY_SIZE; }
    
    /**
     * @brief Get the nonce size required for this algorithm
     */
    [[nodiscard]] size_t nonce_size() const noexcept override { return NONCE_SIZE; }
    
    /**
     * @brief Get the authentication tag size
     */
    [[nodiscard]] size_t tag_size() const noexcept override { return TAG_SIZE; }
    
    /**
     * @brief Encrypt data in-place with authentication
     */
    [[nodiscard]] std::error_code encrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept override;
    
    /**
     * @brief Decrypt data in-place with authentication
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
    [[nodiscard]] static std::error_code encrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
    
    /**
     * @brief One-shot decryption
     */
    [[nodiscard]] static std::error_code decrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<const std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
    
private:
    /**
     * @brief Generate Poly1305 key from ChaCha20
     */
    static void generate_poly_key(
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<std::byte, 32> poly_key
    ) noexcept;
    
    /**
     * @brief Pad data to 16-byte boundary for Poly1305
     */
    static void pad16(poly1305& poly, size_t len) noexcept;
};

} // namespace psyfer::crypto