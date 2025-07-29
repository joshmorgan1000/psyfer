/**
 * @file psy_runtime.hpp
 * @brief Runtime support for psy-c generated code
 */

#pragma once

#include <psyfer/utils/secure.hpp>
#include <cstdint>
#include <cstring>
#include <span>
#include <optional>
#include <vector>
#include <string>
#include <bit>
#include <concepts>

namespace psyfer::serialization {

/**
 * @brief Wire format types
 */
enum class WireType : uint8_t {
    VARINT = 0,      // Variable-length integer
    FIXED64 = 1,     // 64-bit fixed
    BYTES = 2,       // Length-delimited
    FIXED32 = 5,     // 32-bit fixed
};

/**
 * @brief Field header (tag + wire type)
 */
struct FieldHeader {
    uint32_t field_number;
    WireType wire_type;
    
    [[nodiscard]] constexpr uint32_t encode() const noexcept {
        return (field_number << 3) | static_cast<uint8_t>(wire_type);
    }
    
    [[nodiscard]] static constexpr FieldHeader decode(uint32_t value) noexcept {
        return {
            .field_number = value >> 3,
            .wire_type = static_cast<WireType>(value & 0x07)
        };
    }
};

/**
 * @brief Buffer writer for serialization
 */
class BufferWriter {
public:
    explicit BufferWriter(std::span<std::byte> buffer) noexcept
        : buffer_(buffer), position_(0) {}
    
    [[nodiscard]] size_t position() const noexcept { return position_; }
    [[nodiscard]] size_t remaining() const noexcept { 
        return position_ < buffer_.size() ? buffer_.size() - position_ : 0;
    }
    [[nodiscard]] bool has_space(size_t bytes) const noexcept {
        return position_ + bytes <= buffer_.size();
    }
    
    /**
     * @brief Write raw bytes
     */
    bool write_bytes(std::span<const std::byte> data) noexcept {
        if (!has_space(data.size())) return false;
        std::memcpy(buffer_.data() + position_, data.data(), data.size());
        position_ += data.size();
        return true;
    }
    
    /**
     * @brief Write varint (variable-length integer)
     */
    bool write_varint(uint64_t value) noexcept {
        while (value >= 0x80) {
            if (!write_u8(static_cast<uint8_t>(value | 0x80))) return false;
            value >>= 7;
        }
        return write_u8(static_cast<uint8_t>(value));
    }
    
    /**
     * @brief Write signed varint (zigzag encoding)
     */
    bool write_signed_varint(int64_t value) noexcept {
        // Zigzag encoding: (n << 1) ^ (n >> 63)
        uint64_t encoded = static_cast<uint64_t>((value << 1) ^ (value >> 63));
        return write_varint(encoded);
    }
    
    /**
     * @brief Write field header
     */
    bool write_field_header(uint32_t field_number, WireType wire_type) noexcept {
        FieldHeader header{field_number, wire_type};
        return write_varint(header.encode());
    }
    
    /**
     * @brief Write fixed-size integers
     */
    bool write_u8(uint8_t value) noexcept {
        if (!has_space(1)) return false;
        buffer_[position_++] = static_cast<std::byte>(value);
        return true;
    }
    
    bool write_u32(uint32_t value) noexcept {
        if (!has_space(4)) return false;
        std::memcpy(buffer_.data() + position_, &value, 4);
        position_ += 4;
        return true;
    }
    
    bool write_u64(uint64_t value) noexcept {
        if (!has_space(8)) return false;
        std::memcpy(buffer_.data() + position_, &value, 8);
        position_ += 8;
        return true;
    }
    
    bool write_f32(float value) noexcept {
        return write_u32(std::bit_cast<uint32_t>(value));
    }
    
    bool write_f64(double value) noexcept {
        return write_u64(std::bit_cast<uint64_t>(value));
    }
    
    /**
     * @brief Write length-delimited data
     */
    bool write_bytes_field(std::span<const std::byte> data) noexcept {
        if (!write_varint(data.size())) return false;
        return write_bytes(data);
    }
    
    bool write_string_field(std::string_view str) noexcept {
        auto bytes = std::as_bytes(std::span(str));
        return write_bytes_field(bytes);
    }
    
private:
    std::span<std::byte> buffer_;
    size_t position_;
};

/**
 * @brief Buffer reader for deserialization
 */
class BufferReader {
public:
    explicit BufferReader(std::span<const std::byte> buffer) noexcept
        : buffer_(buffer), position_(0) {}
    
    [[nodiscard]] size_t position() const noexcept { return position_; }
    [[nodiscard]] size_t remaining() const noexcept { 
        return position_ < buffer_.size() ? buffer_.size() - position_ : 0;
    }
    [[nodiscard]] bool has_bytes(size_t bytes) const noexcept {
        return position_ + bytes <= buffer_.size();
    }
    
    /**
     * @brief Read raw bytes
     */
    bool read_bytes(std::span<std::byte> out) noexcept {
        if (!has_bytes(out.size())) return false;
        std::memcpy(out.data(), buffer_.data() + position_, out.size());
        position_ += out.size();
        return true;
    }
    
    /**
     * @brief Peek at bytes without advancing position
     */
    [[nodiscard]] std::span<const std::byte> peek_bytes(size_t count) const noexcept {
        if (!has_bytes(count)) return {};
        return buffer_.subspan(position_, count);
    }
    
    /**
     * @brief Skip bytes
     */
    bool skip(size_t bytes) noexcept {
        if (!has_bytes(bytes)) return false;
        position_ += bytes;
        return true;
    }
    
    /**
     * @brief Read varint
     */
    std::optional<uint64_t> read_varint() noexcept {
        uint64_t result = 0;
        int shift = 0;
        
        while (true) {
            if (!has_bytes(1)) return std::nullopt;
            uint8_t byte = static_cast<uint8_t>(buffer_[position_++]);
            
            if (shift >= 64) return std::nullopt; // Overflow
            result |= static_cast<uint64_t>(byte & 0x7F) << shift;
            
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        
        return result;
    }
    
    /**
     * @brief Read signed varint (zigzag decoding)
     */
    std::optional<int64_t> read_signed_varint() noexcept {
        auto encoded = read_varint();
        if (!encoded) return std::nullopt;
        
        // Zigzag decoding: (n >> 1) ^ -(n & 1)
        uint64_t n = *encoded;
        return static_cast<int64_t>((n >> 1) ^ -static_cast<int64_t>(n & 1));
    }
    
    /**
     * @brief Read field header
     */
    std::optional<FieldHeader> read_field_header() noexcept {
        auto encoded = read_varint();
        if (!encoded) return std::nullopt;
        return FieldHeader::decode(static_cast<uint32_t>(*encoded));
    }
    
    /**
     * @brief Read fixed-size integers
     */
    std::optional<uint8_t> read_u8() noexcept {
        if (!has_bytes(1)) return std::nullopt;
        return static_cast<uint8_t>(buffer_[position_++]);
    }
    
    std::optional<uint32_t> read_u32() noexcept {
        if (!has_bytes(4)) return std::nullopt;
        uint32_t value;
        std::memcpy(&value, buffer_.data() + position_, 4);
        position_ += 4;
        return value;
    }
    
    std::optional<uint64_t> read_u64() noexcept {
        if (!has_bytes(8)) return std::nullopt;
        uint64_t value;
        std::memcpy(&value, buffer_.data() + position_, 8);
        position_ += 8;
        return value;
    }
    
    std::optional<float> read_f32() noexcept {
        auto bits = read_u32();
        if (!bits) return std::nullopt;
        return std::bit_cast<float>(*bits);
    }
    
    std::optional<double> read_f64() noexcept {
        auto bits = read_u64();
        if (!bits) return std::nullopt;
        return std::bit_cast<double>(*bits);
    }
    
    /**
     * @brief Read length-delimited data
     */
    std::optional<std::span<const std::byte>> read_bytes_field() noexcept {
        auto length = read_varint();
        if (!length || !has_bytes(*length)) return std::nullopt;
        
        auto data = buffer_.subspan(position_, *length);
        position_ += *length;
        return data;
    }
    
    std::optional<std::string_view> read_string_field() noexcept {
        auto bytes = read_bytes_field();
        if (!bytes) return std::nullopt;
        
        return std::string_view(
            reinterpret_cast<const char*>(bytes->data()),
            bytes->size()
        );
    }
    
private:
    std::span<const std::byte> buffer_;
    size_t position_;
};

/**
 * @brief Size calculation helpers
 */
[[nodiscard]] inline size_t varint_size(uint64_t value) noexcept {
    size_t size = 1;
    while (value >= 0x80) {
        value >>= 7;
        ++size;
    }
    return size;
}

[[nodiscard]] inline size_t signed_varint_size(int64_t value) noexcept {
    uint64_t encoded = static_cast<uint64_t>((value << 1) ^ (value >> 63));
    return varint_size(encoded);
}

[[nodiscard]] inline size_t field_header_size(uint32_t field_number) noexcept {
    return varint_size(field_number << 3);
}

[[nodiscard]] inline size_t bytes_field_size(size_t data_size) noexcept {
    return varint_size(data_size) + data_size;
}

[[nodiscard]] inline size_t string_field_size(std::string_view str) noexcept {
    return bytes_field_size(str.size());
}

/**
 * @brief Encryption/decryption helpers for generated code
 */
template<typename T>
concept HasEncryptedSize = requires(const T& t) {
    { t.encrypted_size() } -> std::convertible_to<size_t>;
};

template<typename T>
concept HasDecrypt = requires(std::span<const std::byte> src, T* target, std::span<const std::byte> key) {
    { T::decrypt(src, target, key) } -> std::convertible_to<size_t>;
};

/**
 * @brief Combined deserialize and decrypt operation
 */
template<typename T>
[[nodiscard]] inline size_t deserialize_and_decrypt(
    std::span<const std::byte> source_buffer,
    T* target,
    std::span<const std::byte> key
) noexcept requires HasDecrypt<T> {
    return T::decrypt(source_buffer, target, key);
}

} // namespace psyfer::serialization