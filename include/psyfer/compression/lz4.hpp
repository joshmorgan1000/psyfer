#pragma once
/**
 * @file lz4.hpp
 * @brief LZ4 compression algorithm implementation
 * 
 * LZ4 is an extremely fast compression algorithm, providing compression speed
 * > 500 MB/s per core, scalable with multi-core CPUs. It features an extremely
 * fast decoder, with speed in multiple GB/s per core.
 */

#include <psyfer.hpp>
#include <cstdint>
#include <limits>
#include <bit>
#include <cstring>
#include <vector>

namespace psyfer::compression {

/**
 * @brief LZ4 compression implementation
 * 
 * This is a clean-room implementation of the LZ4 algorithm.
 * LZ4 is a byte-oriented compression scheme using:
 * - Literal runs (uncompressed bytes)
 * - Match copies (references to previous data)
 * 
 * Format: [token][literals length][literals][offset][match length]
 * Token byte: [literal_length:4][match_length:4]
 */
class lz4 final : public compression_algorithm {
public:
    /**
     * @brief LZ4 block format constants
     */
    static constexpr size_t MIN_MATCH = 4;          // Minimum match length
    static constexpr size_t MAX_DISTANCE = 65535;   // Maximum offset (16-bit)
    static constexpr size_t HASH_TABLE_SIZE = 4096; // Hash table size (12-bit)
    static constexpr size_t ML_BITS = 4;            // Match length bits in token
    static constexpr size_t ML_MASK = (1U << ML_BITS) - 1;
    static constexpr size_t RUN_BITS = 8 - ML_BITS; // Literal length bits
    static constexpr size_t RUN_MASK = (1U << RUN_BITS) - 1;
    
    /**
     * @brief Special markers
     */
    static constexpr uint8_t LAST_LITERAL_SIZE = 5;  // Minimum end literals
    static constexpr uint8_t MFLIMIT = 12;           // Minimum input for match
    
    /**
     * @brief Default constructor
     */
    lz4() noexcept = default;
    
    /**
     * @brief Destructor
     */
    ~lz4() override = default;
    
    /**
     * @brief Get the maximum compressed size for given input
     * 
     * LZ4 worst case is slightly larger than input due to format overhead.
     * Formula: input_size + (input_size/255) + 16
     */
    [[nodiscard]] size_t max_compressed_size(size_t uncompressed_size) const noexcept override;
    
    /**
     * @brief Compress data using LZ4
     * 
     * @param input Input data to compress
     * @param output Output buffer (must be at least max_compressed_size)
     * @return Actual compressed size or error
     */
    [[nodiscard]] result<size_t> compress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept override;
    
    /**
     * @brief Decompress LZ4 data
     * 
     * @param input Compressed data
     * @param output Output buffer (must be large enough for decompressed data)
     * @return Actual decompressed size or error
     */
    [[nodiscard]] result<size_t> decompress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept override;
    
    /**
     * @brief High compression variant (slower but better ratio)
     * 
     * Uses a larger hash table and more aggressive matching.
     */
    [[nodiscard]] result<size_t> compress_hc(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept;
    
    /**
     * @brief Fast compression variant (optimized for speed)
     * 
     * This is the default compress() implementation.
     */
    [[nodiscard]] result<size_t> compress_fast(
        std::span<const std::byte> input,
        std::span<std::byte> output,
        int acceleration = 1
    ) noexcept;
    
private:
    /**
     * @brief Hash function for finding matches
     */
    [[nodiscard]] static uint32_t hash4(const uint8_t* ptr, uint32_t h) noexcept {
        // Simple but effective hash function
        return ((read32(ptr) * 2654435761U) >> (32 - h));
    }
    
    /**
     * @brief Read 32-bit value (little endian)
     */
    [[nodiscard]] static uint32_t read32(const uint8_t* ptr) noexcept {
        uint32_t val;
        std::memcpy(&val, ptr, sizeof(val));
        #ifdef __BIG_ENDIAN__
            val = __builtin_bswap32(val);
        #endif
        return val;
    }
    
    /**
     * @brief Read 16-bit value (little endian)
     */
    [[nodiscard]] static uint16_t read16(const uint8_t* ptr) noexcept {
        uint16_t val;
        std::memcpy(&val, ptr, sizeof(val));
        #ifdef __BIG_ENDIAN__
            val = __builtin_bswap16(val);
        #endif
        return val;
    }
    
    /**
     * @brief Write 16-bit value (little endian)
     */
    static void write16(uint8_t* ptr, uint16_t val) noexcept {
        #ifdef __BIG_ENDIAN__
            val = __builtin_bswap16(val);
        #endif
        std::memcpy(ptr, &val, sizeof(val));
    }
    
    /**
     * @brief Count matching bytes
     */
    [[nodiscard]] static size_t count_match(
        const uint8_t* pIn,
        const uint8_t* pMatch,
        const uint8_t* pInLimit
    ) noexcept;
    
    /**
     * @brief Write literal length
     */
    static uint8_t* write_length(
        uint8_t* op,
        size_t length,
        uint8_t* token,
        bool is_literal
    ) noexcept;
    
    /**
     * @brief Copy memory with possible overlap
     */
    static void wild_copy(uint8_t* dst, const uint8_t* src, uint8_t* dst_end) noexcept;
};

/**
 * @brief LZ4 frame format for streaming
 * 
 * Provides a standard container format with:
 * - Magic number
 * - Frame descriptor
 * - Block sizes
 * - Optional content checksum
 */
class lz4_frame {
public:
    static constexpr uint32_t MAGIC = 0x184D2204;  // LZ4 frame magic number
    
    /**
     * @brief Frame descriptor flags
     */
    struct frame_descriptor {
        bool content_checksum;
        bool content_size;
        bool block_checksum;
        bool block_independence;
        uint32_t max_block_size;
        
        frame_descriptor() 
            : content_checksum(false)
            , content_size(false)
            , block_checksum(false)
            , block_independence(true)
            , max_block_size(65536) {}
    };
    
    /**
     * @brief Compress data with frame format
     */
    [[nodiscard]] static result<std::vector<std::byte>> compress_frame(
        std::span<const std::byte> input,
        const frame_descriptor& desc = {}
    ) noexcept;
    
    /**
     * @brief Decompress frame format
     */
    [[nodiscard]] static result<std::vector<std::byte>> decompress_frame(
        std::span<const std::byte> input
    ) noexcept;
};

} // namespace psyfer::compression