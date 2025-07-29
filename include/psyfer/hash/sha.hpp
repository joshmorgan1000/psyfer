#pragma once
/**
 * @file sha.hpp
 * @brief SHA-256 and SHA-512 hash algorithms for Psyfer
 */

#include <psyfer.hpp>
#include <memory>

namespace psyfer::hash {

/**
 * @brief SHA-256 cryptographic hash function
 * 
 * Produces a 256-bit (32-byte) hash. Uses hardware acceleration
 * when available (CommonCrypto on Apple platforms).
 */
class sha256 final : public hash_algorithm {
public:
    /**
     * @brief Construct a new SHA-256 hasher
     */
    sha256() noexcept;
    
    /**
     * @brief Destroy the SHA-256 hasher
     */
    ~sha256() override;
    
    /**
     * @brief Get the output size (32 bytes)
     */
    [[nodiscard]] size_t output_size() const noexcept override { return 32; }
    
    /**
     * @brief Update the hash with more data
     */
    void update(std::span<const std::byte> data) noexcept override;
    
    /**
     * @brief Finalize the hash and get the result
     * @param output Output buffer (must be at least 32 bytes)
     */
    void finalize(std::span<std::byte> output) noexcept override;
    
    /**
     * @brief Reset the hash state
     */
    void reset() noexcept override;
    
    /**
     * @brief One-shot hash function
     * @param input Data to hash
     * @param output Output buffer (must be at least 32 bytes)
     */
    static void hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept;

private:
    class impl;
    std::unique_ptr<impl> pimpl;
};

/**
 * @brief SHA-512 cryptographic hash function
 * 
 * Produces a 512-bit (64-byte) hash. Uses hardware acceleration
 * when available (CommonCrypto on Apple platforms).
 */
class sha512 final : public hash_algorithm {
public:
    /**
     * @brief Construct a new SHA-512 hasher
     */
    sha512() noexcept;
    
    /**
     * @brief Destroy the SHA-512 hasher
     */
    ~sha512() override;
    
    /**
     * @brief Get the output size (64 bytes)
     */
    [[nodiscard]] size_t output_size() const noexcept override { return 64; }
    
    /**
     * @brief Update the hash with more data
     */
    void update(std::span<const std::byte> data) noexcept override;
    
    /**
     * @brief Finalize the hash and get the result
     * @param output Output buffer (must be at least 64 bytes)
     */
    void finalize(std::span<std::byte> output) noexcept override;
    
    /**
     * @brief Reset the hash state
     */
    void reset() noexcept override;
    
    /**
     * @brief One-shot hash function
     * @param input Data to hash
     * @param output Output buffer (must be at least 64 bytes)
     */
    static void hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept;

private:
    class impl;
    std::unique_ptr<impl> pimpl;
};

/**
 * @brief HMAC-SHA256 implementation
 */
class hmac_sha256 final : public hash_algorithm {
public:
    /**
     * @brief Construct a new HMAC-SHA256
     * @param key The HMAC key (any length)
     */
    explicit hmac_sha256(std::span<const std::byte> key) noexcept;
    
    /**
     * @brief Destroy the HMAC-SHA256
     */
    ~hmac_sha256() override;
    
    /**
     * @brief Get the output size (32 bytes)
     */
    [[nodiscard]] size_t output_size() const noexcept override { return 32; }
    
    /**
     * @brief Update the HMAC with more data
     */
    void update(std::span<const std::byte> data) noexcept override;
    
    /**
     * @brief Finalize the HMAC and get the result
     */
    void finalize(std::span<std::byte> output) noexcept override;
    
    /**
     * @brief Reset the HMAC state
     */
    void reset() noexcept override;
    
    /**
     * @brief One-shot HMAC function
     * @param key The HMAC key
     * @param input Data to authenticate
     * @param output Output buffer (must be at least 32 bytes)
     */
    static void hmac(
        std::span<const std::byte> key,
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept;

private:
    class impl;
    std::unique_ptr<impl> pimpl;
};

/**
 * @brief HMAC-SHA512 implementation
 */
class hmac_sha512 final : public hash_algorithm {
public:
    /**
     * @brief Construct a new HMAC-SHA512
     * @param key The HMAC key (any length)
     */
    explicit hmac_sha512(std::span<const std::byte> key) noexcept;
    
    /**
     * @brief Destroy the HMAC-SHA512
     */
    ~hmac_sha512() override;
    
    /**
     * @brief Get the output size (64 bytes)
     */
    [[nodiscard]] size_t output_size() const noexcept override { return 64; }
    
    /**
     * @brief Update the HMAC with more data
     */
    void update(std::span<const std::byte> data) noexcept override;
    
    /**
     * @brief Finalize the HMAC and get the result
     */
    void finalize(std::span<std::byte> output) noexcept override;
    
    /**
     * @brief Reset the HMAC state
     */
    void reset() noexcept override;
    
    /**
     * @brief One-shot HMAC function
     * @param key The HMAC key
     * @param input Data to authenticate
     * @param output Output buffer (must be at least 64 bytes)
     */
    static void hmac(
        std::span<const std::byte> key,
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept;

private:
    class impl;
    std::unique_ptr<impl> pimpl;
};

} // namespace psyfer::hash