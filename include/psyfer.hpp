#pragma once
/**
 * @file psyfer.hpp
 * @brief Main header file for the Psyfer encryption library.
 * 
 * Psyfer is a modern C++20 library for serialization/deserialization with built-in
 * encryption, hashing, and compression features. Designed for blazing-fast performance
 * with zero-copy operations when possible.
 */

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>
#include <memory>
#include <expected>
#include <system_error>

namespace psyfer {

/**
 * @brief Version information for the Psyfer library
 */
constexpr uint32_t VERSION_MAJOR = 1;
constexpr uint32_t VERSION_MINOR = 0;
constexpr uint32_t VERSION_PATCH = 0;

/**
 * @brief Error codes used throughout the library
 */
enum class error_code : int32_t {
    success = 0,
    invalid_argument,
    invalid_key_size,
    invalid_nonce_size,
    invalid_tag_size,
    invalid_buffer_size,
    encryption_failed,
    decryption_failed,
    authentication_failed,
    compression_failed,
    decompression_failed,
    hash_mismatch,
    memory_allocation_failed,
    not_implemented,
    unknown_error
};

/**
 * @brief Error category for Psyfer errors
 */
class error_category_impl final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "psyfer"; }
    [[nodiscard]] std::string message(int ev) const override;
};

/**
 * @brief Get the global error category instance
 */
[[nodiscard]] const std::error_category& get_error_category() noexcept;

/**
 * @brief Make error code from psyfer error
 */
[[nodiscard]] inline std::error_code make_error_code(error_code e) noexcept {
    return {static_cast<int>(e), get_error_category()};
}

/**
 * @brief Result type for operations that can fail
 */
template<typename T>
using result = std::expected<T, std::error_code>;

/**
 * @brief Common key sizes used in cryptographic operations
 */
namespace key_sizes {
    constexpr size_t AES256 = 32;
    constexpr size_t CHACHA20 = 32;
    constexpr size_t X25519_PRIVATE = 32;
    constexpr size_t X25519_PUBLIC = 32;
    constexpr size_t BLAKE3 = 32;
}

/**
 * @brief Common nonce/IV sizes
 */
namespace nonce_sizes {
    constexpr size_t AES256_GCM = 12;
    constexpr size_t CHACHA20_POLY1305 = 12;
}

/**
 * @brief Common tag sizes for authenticated encryption
 */
namespace tag_sizes {
    constexpr size_t AES256_GCM = 16;
    constexpr size_t CHACHA20_POLY1305 = 16;
}

/**
 * @brief Concept for types that can be used as byte containers
 */
template<typename T>
concept byte_container = requires(T t) {
    { t.data() } -> std::convertible_to<const std::byte*>;
    { t.size() } -> std::convertible_to<std::size_t>;
};

/**
 * @brief Concept for mutable byte containers
 */
template<typename T>
concept mutable_byte_container = byte_container<T> && requires(T t) {
    { t.data() } -> std::convertible_to<std::byte*>;
};

/**
 * @brief Base class for all hash algorithms
 */
class hash_algorithm {
public:
    virtual ~hash_algorithm() = default;
    
    /**
     * @brief Get the output size of this hash algorithm
     */
    [[nodiscard]] virtual size_t output_size() const noexcept = 0;
    
    /**
     * @brief Update the hash with more data
     */
    virtual void update(std::span<const std::byte> data) noexcept = 0;
    
    /**
     * @brief Finalize the hash and get the result
     */
    virtual void finalize(std::span<std::byte> output) noexcept = 0;
    
    /**
     * @brief Reset the hash state
     */
    virtual void reset() noexcept = 0;
};

/**
 * @brief Base class for encryption algorithms
 */
class encryption_algorithm {
public:
    virtual ~encryption_algorithm() = default;
    
    /**
     * @brief Get the key size required for this algorithm
     */
    [[nodiscard]] virtual size_t key_size() const noexcept = 0;
    
    /**
     * @brief Get the nonce/IV size required for this algorithm
     */
    [[nodiscard]] virtual size_t nonce_size() const noexcept = 0;
    
    /**
     * @brief Get the authentication tag size (0 if not authenticated)
     */
    [[nodiscard]] virtual size_t tag_size() const noexcept = 0;
    
    /**
     * @brief Encrypt data in-place
     * @param data The data to encrypt (modified in-place)
     * @param key The encryption key
     * @param nonce The nonce/IV
     * @param tag Output buffer for authentication tag (if applicable)
     * @param aad Additional authenticated data (optional)
     * @return Error code on failure
     */
    [[nodiscard]] virtual std::error_code encrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept = 0;
    
    /**
     * @brief Decrypt data in-place
     * @param data The data to decrypt (modified in-place)
     * @param key The decryption key
     * @param nonce The nonce/IV
     * @param tag The authentication tag to verify (if applicable)
     * @param aad Additional authenticated data (optional)
     * @return Error code on failure
     */
    [[nodiscard]] virtual std::error_code decrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<const std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept = 0;
};

/**
 * @brief Base class for compression algorithms
 */
class compression_algorithm {
public:
    virtual ~compression_algorithm() = default;
    
    /**
     * @brief Get the maximum compressed size for a given input size
     * @param uncompressed_size Size of uncompressed data
     * @return Maximum possible compressed size
     */
    [[nodiscard]] virtual size_t max_compressed_size(size_t uncompressed_size) const noexcept = 0;
    
    /**
     * @brief Compress data
     * @param input The data to compress
     * @param output Output buffer for compressed data
     * @return Actual compressed size or error
     */
    [[nodiscard]] virtual result<size_t> compress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept = 0;
    
    /**
     * @brief Decompress data
     * @param input The compressed data
     * @param output Output buffer for decompressed data
     * @return Actual decompressed size or error
     */
    [[nodiscard]] virtual result<size_t> decompress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept = 0;
};

} // namespace psyfer

// Enable std::error_code integration
template<>
struct std::is_error_code_enum<psyfer::error_code> : std::true_type {};

// Include all algorithm implementations
#include <psyfer/hash/sha.hpp>
#include <psyfer/hash/xxhash3.hpp>
#include <psyfer/mac/aes_cmac.hpp>
#include <psyfer/kdf/hkdf.hpp>
#include <psyfer/crypto/aes256.hpp>
#include <psyfer/crypto/chacha20.hpp>
#include <psyfer/crypto/ed25519.hpp>
#include <psyfer/crypto/x25519.hpp>
#include <psyfer/compression/lz4.hpp>
#include <psyfer/compression/fpc.hpp>
#include <psyfer/utils/secure.hpp>
