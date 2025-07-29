#pragma once
/**
 * @file xxhash3.hpp
 * @brief xxHash3 implementation - extremely fast non-cryptographic hash
 * 
 * xxHash3 is the latest evolution of xxHash, providing:
 * - Excellent performance on modern CPUs (>30 GB/s on high-end CPUs)
 * - High quality hash distribution
 * - Both 64-bit and 128-bit variants
 * - Streaming and one-shot APIs
 * 
 * This is a non-cryptographic hash function suitable for:
 * - Hash tables
 * - Checksums
 * - Deduplication
 * - Data fingerprinting
 * 
 * NOT suitable for:
 * - Cryptographic purposes
 * - Security-sensitive applications
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace psyfer::hash {

/**
 * @brief xxHash3 24-bit implementation
 * 
 * Specialized variant producing 24-bit output for space-constrained applications.
 * Suitable for hash tables with up to ~16M entries or compact data structures.
 */
class xxhash3_24 {
public:
    static constexpr size_t HASH_SIZE = 3; // 24 bits
    
    /**
     * @brief One-shot hash function
     * 
     * @param data Data to hash
     * @param seed Optional seed value (default: 0)
     * @return 24-bit hash value (in lower 24 bits of uint32_t)
     */
    [[nodiscard]] static uint32_t hash(
        std::span<const std::byte> data,
        uint64_t seed = 0
    ) noexcept;
    
    /**
     * @brief Hash a string
     */
    [[nodiscard]] static uint32_t hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
};

/**
 * @brief xxHash3 32-bit implementation
 */
class xxhash3_32 {
public:
    static constexpr size_t HASH_SIZE = 4; // 32 bits
    
    /**
     * @brief One-shot hash function
     * 
     * @param data Data to hash
     * @param seed Optional seed value (default: 0)
     * @return 32-bit hash value
     */
    [[nodiscard]] static uint32_t hash(
        std::span<const std::byte> data,
        uint64_t seed = 0
    ) noexcept;
    
    /**
     * @brief Hash a string
     */
    [[nodiscard]] static uint32_t hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
};

/**
 * @brief xxHash3 64-bit implementation
 */
class xxhash3_64 {
public:
    static constexpr size_t HASH_SIZE = 8; // 64 bits
    
    /**
     * @brief One-shot hash function
     * 
     * @param data Data to hash
     * @param seed Optional seed value (default: 0)
     * @return 64-bit hash value
     */
    [[nodiscard]] static uint64_t hash(
        std::span<const std::byte> data,
        uint64_t seed = 0
    ) noexcept;
    
    /**
     * @brief Hash a string
     */
    [[nodiscard]] static uint64_t hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
    
    /**
     * @brief Streaming hash context
     */
    class hasher {
    public:
        /**
         * @brief Initialize with optional seed
         */
        explicit hasher(uint64_t seed = 0) noexcept;
        
        /**
         * @brief Update hash with more data
         */
        hasher& update(std::span<const std::byte> data) noexcept;
        
        /**
         * @brief Update with string data
         */
        hasher& update(std::string_view str) noexcept {
            return update(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(str.data()),
                    str.size()
                )
            );
        }
        
        /**
         * @brief Finalize and get hash value
         */
        [[nodiscard]] uint64_t finalize() noexcept;
        
        /**
         * @brief Reset to initial state
         */
        void reset(uint64_t seed = 0) noexcept;
        
    private:
        static constexpr size_t BUFFER_SIZE = 256;
        static constexpr size_t ACC_NB = 8;
        
        alignas(32) std::array<uint64_t, ACC_NB> acc_;
        alignas(32) std::array<std::byte, BUFFER_SIZE> buffer_;
        size_t buffer_size_;
        size_t total_len_;
        uint64_t seed_;
    };
};

/**
 * @brief xxHash3 128-bit implementation
 */
class xxhash3_128 {
public:
    static constexpr size_t HASH_SIZE = 16; // 128 bits
    
    /**
     * @brief 128-bit hash result
     */
    struct hash128 {
        uint64_t low;
        uint64_t high;
        
        bool operator==(const hash128& other) const noexcept {
            return low == other.low && high == other.high;
        }
        
        bool operator!=(const hash128& other) const noexcept {
            return !(*this == other);
        }
    };
    
    /**
     * @brief One-shot hash function
     * 
     * @param data Data to hash
     * @param seed Optional seed value (default: 0)
     * @return 128-bit hash value
     */
    [[nodiscard]] static hash128 hash(
        std::span<const std::byte> data,
        uint64_t seed = 0
    ) noexcept;
    
    /**
     * @brief Hash a string
     */
    [[nodiscard]] static hash128 hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
    
    /**
     * @brief Streaming hash context
     */
    class hasher {
    public:
        /**
         * @brief Initialize with optional seed
         */
        explicit hasher(uint64_t seed = 0) noexcept;
        
        /**
         * @brief Update hash with more data
         */
        hasher& update(std::span<const std::byte> data) noexcept;
        
        /**
         * @brief Update with string data
         */
        hasher& update(std::string_view str) noexcept {
            return update(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(str.data()),
                    str.size()
                )
            );
        }
        
        /**
         * @brief Finalize and get hash value
         */
        [[nodiscard]] hash128 finalize() noexcept;
        
        /**
         * @brief Reset to initial state
         */
        void reset(uint64_t seed = 0) noexcept;
        
    private:
        static constexpr size_t BUFFER_SIZE = 256;
        static constexpr size_t ACC_NB = 8;
        
        alignas(32) std::array<uint64_t, ACC_NB> acc_;
        alignas(32) std::array<std::byte, BUFFER_SIZE> buffer_;
        size_t buffer_size_;
        size_t total_len_;
        uint64_t seed_;
    };
};

/**
 * @brief Convenience aliases
 */
using xxh3_24 = xxhash3_24;
using xxh3_32 = xxhash3_32;
using xxh3_64 = xxhash3_64;
using xxh3_128 = xxhash3_128;

} // namespace psyfer::hash