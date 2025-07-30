/**
 * @file fpc.cpp
 * @brief FPC (Fast Pfor Compression) implementation
 */

#include <psyfer.hpp>
#include <bit>
#include <cstring>
#include <algorithm>

namespace psyfer::crypto {

namespace {
    /**
     * @brief Convert double to uint64_t bits
     */
    [[nodiscard]] inline uint64_t double_to_bits(double value) noexcept {
        return std::bit_cast<uint64_t>(value);
    }
    
    /**
     * @brief Convert uint64_t bits to double
     */
    [[nodiscard]] inline double bits_to_double(uint64_t bits) noexcept {
        return std::bit_cast<double>(bits);
    }
    
    /**
     * @brief Encode non-zero bytes of a value
     */
    void encode_nonzero_bytes(uint64_t value, uint8_t len, uint8_t* output) noexcept {
        // Unrolled for performance
        switch (len) {
            case 8:
                output[7] = static_cast<uint8_t>((value >> 56) & 0xFF);
                [[fallthrough]];
            case 7:
                output[6] = static_cast<uint8_t>((value >> 48) & 0xFF);
                [[fallthrough]];
            case 6:
                output[5] = static_cast<uint8_t>((value >> 40) & 0xFF);
                [[fallthrough]];
            case 5:
                output[4] = static_cast<uint8_t>((value >> 32) & 0xFF);
                [[fallthrough]];
            case 4:
                output[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
                [[fallthrough]];
            case 3:
                output[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
                [[fallthrough]];
            case 2:
                output[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
                [[fallthrough]];
            case 1:
                output[0] = static_cast<uint8_t>(value & 0xFF);
                [[fallthrough]];
            case 0:
                break;
        }
    }
    
    /**
     * @brief Decode partial little-endian uint64
     */
    [[nodiscard]] uint64_t decode_partial_uint64(const uint8_t* data, uint8_t len) noexcept {
        uint64_t result = 0;
        
        // Unrolled for performance
        switch (len) {
            case 8:
                result |= static_cast<uint64_t>(data[7]) << 56;
                [[fallthrough]];
            case 7:
                result |= static_cast<uint64_t>(data[6]) << 48;
                [[fallthrough]];
            case 6:
                result |= static_cast<uint64_t>(data[5]) << 40;
                [[fallthrough]];
            case 5:
                result |= static_cast<uint64_t>(data[4]) << 32;
                [[fallthrough]];
            case 4:
                result |= static_cast<uint64_t>(data[3]) << 24;
                [[fallthrough]];
            case 3:
                result |= static_cast<uint64_t>(data[2]) << 16;
                [[fallthrough]];
            case 2:
                result |= static_cast<uint64_t>(data[1]) << 8;
                [[fallthrough]];
            case 1:
                result |= static_cast<uint64_t>(data[0]);
                [[fallthrough]];
            case 0:
                break;
        }
        
        return result;
    }
}

// FPC Writer implementation

fpc_writer::fpc_writer(std::vector<uint8_t>& output, fpc_compression_level level) noexcept
    : output_(output)
    , compression_level_(static_cast<uint8_t>(level)) {
    
    size_t table_size = 1ULL << compression_level_;
    fcm_ = std::make_unique<fcm_predictor>(table_size);
    dfcm_ = std::make_unique<dfcm_predictor>(table_size);
    
    headers_.reserve(MAX_RECORDS_PER_BLOCK);
    values_.reserve(MAX_RECORDS_PER_BLOCK * 8);
}

void fpc_writer::write_header() noexcept {
    if (!header_written_) {
        output_.push_back(compression_level_);
        bytes_written_++;
        header_written_ = true;
    }
}

void fpc_writer::write_float(double value) noexcept {
    write_header();
    encode_value(double_to_bits(value));
}

void fpc_writer::write_floats(std::span<const double> values) noexcept {
    write_header();
    for (double value : values) {
        encode_value(double_to_bits(value));
    }
}

void fpc_writer::encode_value(uint64_t value) noexcept {
    // Store value for pairing
    if (record_count_ % 2 == 0) {
        last_value_ = value;
        record_count_++;
        return;
    }
    
    // Encode pair
    uint64_t v1 = last_value_;
    uint64_t v2 = value;
    
    // Compute predictions and differences
    uint64_t fcm_delta1 = fcm_->predict() ^ v1;
    fcm_->update(v1);
    
    uint64_t dfcm_delta1 = dfcm_->predict() ^ v1;
    dfcm_->update(v1);
    
    uint64_t fcm_delta2 = fcm_->predict() ^ v2;
    fcm_->update(v2);
    
    uint64_t dfcm_delta2 = dfcm_->predict() ^ v2;
    dfcm_->update(v2);
    
    // Choose best predictor for each value
    uint64_t delta1;
    predictor_type type1;
    if (fcm_delta1 <= dfcm_delta1) {
        delta1 = fcm_delta1;
        type1 = predictor_type::FCM;
    } else {
        delta1 = dfcm_delta1;
        type1 = predictor_type::DFCM;
    }
    
    uint64_t delta2;
    predictor_type type2;
    if (fcm_delta2 <= dfcm_delta2) {
        delta2 = fcm_delta2;
        type2 = predictor_type::FCM;
    } else {
        delta2 = dfcm_delta2;
        type2 = predictor_type::DFCM;
    }
    
    // Count non-zero bytes
    uint8_t len1 = 8 - count_leading_zero_bytes(delta1);
    uint8_t len2 = 8 - count_leading_zero_bytes(delta2);
    
    // Handle special case: length 4 is encoded as 5
    if (len1 == 4) len1 = 5;
    if (len2 == 4) len2 = 5;
    
    // Create header
    pair_header header;
    header.h1_len = (len1 >= 5) ? len1 - 1 : len1;
    header.h1_type = type1;
    header.h2_len = (len2 >= 5) ? len2 - 1 : len2;
    header.h2_type = type2;
    
    headers_.push_back(header.encode());
    
    // Encode values
    size_t old_size = values_.size();
    values_.resize(old_size + len1 + len2);
    
    encode_nonzero_bytes(delta1, len1, values_.data() + old_size);
    encode_nonzero_bytes(delta2, len2, values_.data() + old_size + len1);
    
    record_count_++;  // We already incremented once for the first value, so total is 2
    
    // Flush if block is full
    if (record_count_ >= MAX_RECORDS_PER_BLOCK) {
        flush_block();
    }
}

void fpc_writer::flush() noexcept {
    if (record_count_ > 0) {
        // Handle unpaired value
        if (record_count_ % 2 == 1) {
            encode_value(0);  // Pair with zero
            // Remove the dummy value's data
            pair_header last_header = pair_header::decode(headers_.back());
            values_.resize(values_.size() - last_header.h2_len);
        }
        flush_block();
    }
}

uint8_t fpc_writer::count_leading_zero_bytes(uint64_t value) noexcept {
    if (value == 0) return 8;
    
    #if defined(__GNUC__) || defined(__clang__)
        // Use builtin for better performance
        int leading_zeros = __builtin_clzll(value);
        return static_cast<uint8_t>(leading_zeros / 8);
    #else
        // Portable implementation
        uint8_t count = 0;
        while ((value & 0xFF00000000000000ULL) == 0 && count < 8) {
            value <<= 8;
            count++;
        }
        return count;
    #endif
}

void fpc_writer::flush_block() noexcept {
    if (record_count_ == 0) return;
    
    size_t block_size = BLOCK_HEADER_SIZE + headers_.size() + values_.size();
    size_t old_output_size = output_.size();
    output_.resize(old_output_size + block_size);
    
    uint8_t* block_start = output_.data() + old_output_size;
    
    // Write block header (6 bytes)
    // First 3 bytes: number of records (little-endian 24-bit)
    block_start[0] = static_cast<uint8_t>(record_count_ & 0xFF);
    block_start[1] = static_cast<uint8_t>((record_count_ >> 8) & 0xFF);
    block_start[2] = static_cast<uint8_t>((record_count_ >> 16) & 0xFF);
    
    // Next 3 bytes: block size (little-endian 24-bit)
    block_start[3] = static_cast<uint8_t>(block_size & 0xFF);
    block_start[4] = static_cast<uint8_t>((block_size >> 8) & 0xFF);
    block_start[5] = static_cast<uint8_t>((block_size >> 16) & 0xFF);
    
    // Copy headers
    std::memcpy(block_start + BLOCK_HEADER_SIZE, headers_.data(), headers_.size());
    
    // Copy values
    std::memcpy(block_start + BLOCK_HEADER_SIZE + headers_.size(), 
                values_.data(), values_.size());
    
    bytes_written_ += block_size;
    
    // Reset for next block
    headers_.clear();
    values_.clear();
    record_count_ = 0;
}

// FPC Reader implementation

fpc_reader::fpc_reader(std::span<const uint8_t> input) noexcept
    : input_(input) {
    read_header();
}

bool fpc_reader::read_header() noexcept {
    if (pos_ >= input_.size()) return false;
    
    compression_level_ = input_[pos_++];
    
    size_t table_size = 1ULL << compression_level_;
    fcm_ = std::make_unique<fcm_predictor>(table_size);
    dfcm_ = std::make_unique<dfcm_predictor>(table_size);
    
    return true;
}

std::optional<double> fpc_reader::read_float() noexcept {
    // Read next block if needed
    if (block_values_.empty() || block_pos_ >= block_values_.size()) {
        if (!read_block()) {
            return std::nullopt;
        }
    }
    
    return bits_to_double(block_values_[block_pos_++]);
}

size_t fpc_reader::read_floats(std::span<double> values) noexcept {
    size_t read = 0;
    
    while (read < values.size()) {
        if (auto value = read_float()) {
            values[read++] = *value;
        } else {
            break;
        }
    }
    
    return read;
}

bool fpc_reader::read_block() noexcept {
    if (pos_ + fpc_reader::BLOCK_HEADER_SIZE > input_.size()) return false;
    
    // Read block header
    uint32_t n_records = input_[pos_] | 
                        (input_[pos_ + 1] << 8) | 
                        (input_[pos_ + 2] << 16);
    
    uint32_t block_size = input_[pos_ + 3] | 
                         (input_[pos_ + 4] << 8) | 
                         (input_[pos_ + 5] << 16);
    
    pos_ += fpc_reader::BLOCK_HEADER_SIZE;
    
    if (pos_ + block_size - fpc_reader::BLOCK_HEADER_SIZE > input_.size()) return false;
    
    // Calculate header count (pairs)
    size_t header_count = (n_records + 1) / 2;
    
    if (pos_ + header_count > input_.size()) return false;
    
    // Read all values in the block
    block_values_.clear();
    block_values_.reserve(n_records);
    
    const uint8_t* headers = input_.data() + pos_;
    const uint8_t* values = headers + header_count;
    size_t value_pos = 0;
    
    for (size_t i = 0; i < header_count; ++i) {
        pair_header header = pair_header::decode(headers[i]);
        
        // Decode first value
        if (value_pos + header.h1_len > block_size - fpc_reader::BLOCK_HEADER_SIZE - header_count) {
            return false;
        }
        
        uint64_t delta1 = decode_partial_uint64(values + value_pos, header.h1_len);
        value_pos += header.h1_len;
        
        // Apply predictor
        uint64_t v1;
        if (header.h1_type == predictor_type::FCM) {
            v1 = fcm_->predict() ^ delta1;
        } else {
            v1 = dfcm_->predict() ^ delta1;
        }
        fcm_->update(v1);
        dfcm_->update(v1);
        block_values_.push_back(v1);
        
        // Decode second value (if not last unpaired)
        if (block_values_.size() < n_records) {
            if (value_pos + header.h2_len > block_size - fpc_reader::BLOCK_HEADER_SIZE - header_count) {
                return false;
            }
            
            uint64_t delta2 = decode_partial_uint64(values + value_pos, header.h2_len);
            value_pos += header.h2_len;
            
            // Apply predictor
            uint64_t v2;
            if (header.h2_type == predictor_type::FCM) {
                v2 = fcm_->predict() ^ delta2;
            } else {
                v2 = dfcm_->predict() ^ delta2;
            }
            fcm_->update(v2);
            dfcm_->update(v2);
            block_values_.push_back(v2);
        }
    }
    
    pos_ += block_size - fpc_reader::BLOCK_HEADER_SIZE;
    block_pos_ = 0;
    
    return true;
}

// Convenience functions

std::vector<uint8_t> fpc_compress(
    std::span<const double> input,
    fpc_compression_level level
) noexcept {
    std::vector<uint8_t> output;
    output.reserve(input.size() * sizeof(double) / 2);  // Estimate
    
    fpc_writer writer(output, level);
    writer.write_floats(input);
    writer.flush();
    
    return output;
}

size_t fpc_decompress(
    std::span<const uint8_t> input,
    std::span<double> output
) noexcept {
    fpc_reader reader(input);
    return reader.read_floats(output);
}

size_t fpc_max_decompressed_size(std::span<const uint8_t> input) noexcept {
    if (input.size() < 1 + fpc_reader::BLOCK_HEADER_SIZE) return 0;
    
    size_t pos = 1;  // Skip compression level
    size_t total = 0;
    
    while (pos + fpc_reader::BLOCK_HEADER_SIZE <= input.size()) {
        uint32_t n_records = input[pos] | 
                            (input[pos + 1] << 8) | 
                            (input[pos + 2] << 16);
        
        uint32_t block_size = input[pos + 3] | 
                             (input[pos + 4] << 8) | 
                             (input[pos + 5] << 16);
        
        total += n_records;
        pos += block_size;
    }
    
    return total;
}

} // namespace psyfer::crypto