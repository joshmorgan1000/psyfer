/**
 * @file fpc.hpp
 * @brief FPC (Fast Pfor Compression) for floating-point data
 * 
 * FPC is a fast, lossless compression algorithm for IEEE 754 floating-point data.
 * Based on Burtscher and Ratanaworabhan's FPC algorithm.
 */

#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace psyfer::compression {

/**
 * @brief FPC compression levels
 */
enum class fpc_compression_level : uint8_t {
    DEFAULT = 10,
    MIN = 1,
    MAX = 32
};

/**
 * @brief FPC predictor types
 */
enum class predictor_type : uint8_t {
    FCM = 0,   // Finite Context Method
    DFCM = 1   // Differential Finite Context Method
};

/**
 * @brief Header for a pair of compressed values
 */
struct pair_header {
    uint8_t h1_len;          // Length of first value (0-7)
    predictor_type h1_type;
    uint8_t h2_len;          // Length of second value (0-7)
    predictor_type h2_type;
    
    [[nodiscard]] constexpr uint8_t encode() const noexcept {
        // Each header is 4 bits: type in bit 3, len in bits 0-2
        uint8_t h1_bits = (static_cast<uint8_t>(h1_type) << 3) | h1_len;
        uint8_t h2_bits = (static_cast<uint8_t>(h2_type) << 3) | h2_len;
        return (h1_bits << 4) | h2_bits;
    }
    
    static constexpr pair_header decode(uint8_t byte) noexcept {
        pair_header h;
        // First header in upper 4 bits
        uint8_t h1_bits = (byte >> 4) & 0x0F;
        h.h1_type = static_cast<predictor_type>((h1_bits >> 3) & 1);
        h.h1_len = h1_bits & 0x07;
        
        // Second header in lower 4 bits
        uint8_t h2_bits = byte & 0x0F;
        h.h2_type = static_cast<predictor_type>((h2_bits >> 3) & 1);
        h.h2_len = h2_bits & 0x07;
        
        // Handle special case where len 4 is encoded as 3
        if (h.h1_len >= 4) h.h1_len++;
        if (h.h2_len >= 4) h.h2_len++;
        
        return h;
    }
};

/**
 * @brief Base predictor interface
 */
class predictor {
public:
    virtual ~predictor() = default;
    
    /**
     * @brief Predict the next value
     */
    [[nodiscard]] virtual uint64_t predict() const noexcept = 0;
    
    /**
     * @brief Update the predictor with the actual value
     */
    virtual void update(uint64_t actual) noexcept = 0;
};

/**
 * @brief Finite Context Method predictor
 */
class fcm_predictor final : public predictor {
public:
    /**
     * @brief Construct FCM predictor
     * @param table_size Must be a power of 2
     */
    explicit fcm_predictor(size_t table_size) noexcept
        : table_(table_size, 0)
        , size_mask_(table_size - 1)
        , last_hash_(0) {}
    
    [[nodiscard]] uint64_t predict() const noexcept override {
        return table_[last_hash_];
    }
    
    void update(uint64_t actual) noexcept override {
        table_[last_hash_] = actual;
        last_hash_ = hash(actual);
    }

private:
    [[nodiscard]] uint64_t hash(uint64_t actual) const noexcept {
        return ((last_hash_ << 6) ^ (actual >> 48)) & size_mask_;
    }
    
    std::vector<uint64_t> table_;
    uint64_t size_mask_;
    uint64_t last_hash_;
};

/**
 * @brief Differential Finite Context Method predictor
 */
class dfcm_predictor final : public predictor {
public:
    /**
     * @brief Construct DFCM predictor
     * @param table_size Must be a power of 2
     */
    explicit dfcm_predictor(size_t table_size) noexcept
        : table_(table_size, 0)
        , size_mask_(table_size - 1)
        , last_hash_(0)
        , last_value_(0) {}
    
    [[nodiscard]] uint64_t predict() const noexcept override {
        return table_[last_hash_] + last_value_;
    }
    
    void update(uint64_t actual) noexcept override {
        table_[last_hash_] = actual - last_value_;
        last_hash_ = hash(actual);
        last_value_ = actual;
    }

private:
    [[nodiscard]] uint64_t hash(uint64_t actual) const noexcept {
        return ((last_hash_ << 2) ^ ((actual - last_value_) >> 40)) & size_mask_;
    }
    
    std::vector<uint64_t> table_;
    uint64_t size_mask_;
    uint64_t last_hash_;
    uint64_t last_value_;
};

/**
 * @brief FPC writer for compressing floating-point data
 */
class fpc_writer {
public:
    static constexpr size_t MAX_RECORDS_PER_BLOCK = 32768;
    static constexpr size_t BLOCK_HEADER_SIZE = 6;
    
    /**
     * @brief Construct FPC writer with default compression
     */
    explicit fpc_writer(std::vector<uint8_t>& output) noexcept
        : fpc_writer(output, fpc_compression_level::DEFAULT) {}
    
    /**
     * @brief Construct FPC writer with specified compression level
     */
    fpc_writer(std::vector<uint8_t>& output, fpc_compression_level level) noexcept;
    
    /**
     * @brief Write a single float64 value
     */
    void write_float(double value) noexcept;
    
    /**
     * @brief Write multiple float64 values
     */
    void write_floats(std::span<const double> values) noexcept;
    
    /**
     * @brief Flush any buffered data
     */
    void flush() noexcept;
    
    /**
     * @brief Get the number of bytes written
     */
    [[nodiscard]] size_t bytes_written() const noexcept { return bytes_written_; }

private:
    void write_header() noexcept;
    void encode_value(uint64_t value) noexcept;
    void flush_block() noexcept;
    
    [[nodiscard]] static uint8_t count_leading_zero_bytes(uint64_t value) noexcept;
    
    std::vector<uint8_t>& output_;
    uint8_t compression_level_;
    bool header_written_ = false;
    
    // Predictors
    std::unique_ptr<fcm_predictor> fcm_;
    std::unique_ptr<dfcm_predictor> dfcm_;
    
    // Block buffers
    std::vector<uint8_t> headers_;
    std::vector<uint8_t> values_;
    
    // State
    uint64_t last_value_ = 0;
    size_t record_count_ = 0;
    size_t bytes_written_ = 0;
};

/**
 * @brief FPC reader for decompressing floating-point data
 */
class fpc_reader {
public:
    static constexpr size_t BLOCK_HEADER_SIZE = 6;
public:
    /**
     * @brief Construct FPC reader
     */
    explicit fpc_reader(std::span<const uint8_t> input) noexcept;
    
    /**
     * @brief Read a single float64 value
     * @return The value, or nullopt if no more data
     */
    [[nodiscard]] std::optional<double> read_float() noexcept;
    
    /**
     * @brief Read multiple float64 values
     * @return Number of values read
     */
    size_t read_floats(std::span<double> values) noexcept;
    
    /**
     * @brief Check if more data is available
     */
    [[nodiscard]] bool has_data() const noexcept { 
        return (block_pos_ < block_values_.size()) || (pos_ < input_.size()); 
    }

private:
    bool read_header() noexcept;
    bool read_block() noexcept;
    [[nodiscard]] std::optional<uint64_t> decode_next_value() noexcept;
    
    std::span<const uint8_t> input_;
    size_t pos_ = 0;
    uint8_t compression_level_ = 0;
    
    // Predictors
    std::unique_ptr<fcm_predictor> fcm_;
    std::unique_ptr<dfcm_predictor> dfcm_;
    
    // Current block data
    std::vector<uint64_t> block_values_;
    size_t block_pos_ = 0;
};

/**
 * @brief Compress floating-point data using FPC
 * @param input Input floating-point data
 * @param level Compression level
 * @return Compressed data
 */
[[nodiscard]] std::vector<uint8_t> fpc_compress(
    std::span<const double> input,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept;

/**
 * @brief Decompress FPC-compressed data
 * @param input Compressed data
 * @param output Output buffer for decompressed data
 * @return Number of floats decompressed, or 0 on error
 */
size_t fpc_decompress(
    std::span<const uint8_t> input,
    std::span<double> output
) noexcept;

/**
 * @brief Get the maximum decompressed size for a compressed buffer
 * @param input Compressed data
 * @return Maximum number of doubles that could be decompressed
 */
[[nodiscard]] size_t fpc_max_decompressed_size(std::span<const uint8_t> input) noexcept;

} // namespace psyfer::compression