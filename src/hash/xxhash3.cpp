/**
 * @file xxhash3.cpp
 * @brief xxHash3 implementation
 */

#include <psyfer.hpp>
#include <cstring>
#include <bit>

namespace psyfer {

// xxHash3 constants
namespace {
    constexpr uint64_t PRIME64_1 = 0x9E3779B185EBCA87ULL;
    constexpr uint64_t PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
    constexpr uint64_t PRIME64_3 = 0x165667B19E3779F9ULL;
    constexpr uint64_t PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
    constexpr uint64_t PRIME64_5 = 0x27D4EB2F165667C5ULL;
    
    // Secret key for xxHash3 (complete 192 bytes as per spec)
    alignas(64) constexpr uint8_t kSecret[192] = {
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
        0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
        0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
        0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
        0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
        0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
        0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
        0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
        0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
        0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
        0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
        0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
    };
    
    // Additional xxHash3 constants
    [[maybe_unused]] constexpr uint32_t PRIME32_1 = 0x9E3779B1U;
    constexpr uint32_t PRIME32_2 = 0x85EBCA77U;
    constexpr uint32_t PRIME32_3 = 0xC2B2AE3DU;
    
    // Multiply 64x64 -> 128
    [[nodiscard]] inline std::pair<uint64_t, uint64_t> mul128(uint64_t a, uint64_t b) noexcept {
        #ifdef __SIZEOF_INT128__
            __uint128_t product = static_cast<__uint128_t>(a) * b;
            return {static_cast<uint64_t>(product), static_cast<uint64_t>(product >> 64)};
        #else
            // Portable fallback
            uint64_t a_lo = a & 0xFFFFFFFF;
            uint64_t a_hi = a >> 32;
            uint64_t b_lo = b & 0xFFFFFFFF;
            uint64_t b_hi = b >> 32;
            
            uint64_t p0 = a_lo * b_lo;
            uint64_t p1 = a_lo * b_hi;
            uint64_t p2 = a_hi * b_lo;
            uint64_t p3 = a_hi * b_hi;
            
            uint64_t cy = (p0 >> 32) + (p1 & 0xFFFFFFFF) + (p2 & 0xFFFFFFFF);
            
            return {
                (cy << 32) | (p0 & 0xFFFFFFFF),
                p3 + (p1 >> 32) + (p2 >> 32) + (cy >> 32)
            };
        #endif
    }
    
    // Mix two 64-bit values to produce 128-bit result
    [[nodiscard]] [[maybe_unused]] inline std::pair<uint64_t, uint64_t> mix128(uint64_t a, uint64_t b) noexcept {
        auto [lo, hi] = mul128(a, b);
        return {a + lo, b + hi};
    }
    
    // Read 64-bit little endian
    [[nodiscard]] inline uint64_t read64_le(const std::byte* ptr) noexcept {
        uint64_t val;
        std::memcpy(&val, ptr, sizeof(val));
        if constexpr (std::endian::native == std::endian::big) {
            val = std::byteswap(val);
        }
        return val;
    }
    
    // Read 32-bit little endian
    [[nodiscard]] inline uint32_t read32_le(const std::byte* ptr) noexcept {
        uint32_t val;
        std::memcpy(&val, ptr, sizeof(val));
        if constexpr (std::endian::native == std::endian::big) {
            val = std::byteswap(val);
        }
        return val;
    }
    
    // xxHash3 mix function
    [[nodiscard]] inline uint64_t xxh3_mix16(
        const std::byte* data,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint64_t data_lo = read64_le(data) ^ (read64_le(reinterpret_cast<const std::byte*>(secret)) + seed);
        uint64_t data_hi = read64_le(data + 8) ^ (read64_le(reinterpret_cast<const std::byte*>(secret + 8)) - seed);
        auto [lo, hi] = mul128(data_lo, data_hi);
        return lo ^ hi;
    }
    
    // xxHash3 avalanche
    [[nodiscard]] inline uint64_t xxh3_avalanche(uint64_t h64) noexcept {
        h64 ^= h64 >> 37;
        h64 *= 0x165667919E3779F9ULL;
        h64 ^= h64 >> 32;
        return h64;
    }
    
    // Process 1-3 bytes
    [[nodiscard]] inline uint64_t xxh3_len_1to3(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint8_t c1 = static_cast<uint8_t>(data[0]);
        uint8_t c2 = static_cast<uint8_t>(data[len >> 1]);
        uint8_t c3 = static_cast<uint8_t>(data[len - 1]);
        uint32_t combined = ((uint32_t)c1 << 16) | ((uint32_t)c2 << 24) | 
                           ((uint32_t)c3 << 0) | ((uint32_t)len << 8);
        uint64_t bitflip = (read64_le(reinterpret_cast<const std::byte*>(secret)) ^ 
                           read64_le(reinterpret_cast<const std::byte*>(secret + 8))) + seed;
        return xxh3_avalanche(combined ^ bitflip);
    }
    
    // Process 4-8 bytes
    [[nodiscard]] inline uint64_t xxh3_len_4to8(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint32_t data32_1 = read32_le(data);
        uint32_t data32_2 = read32_le(data + len - 4);
        uint64_t data64 = data32_1 + ((uint64_t)data32_2 << 32);
        uint64_t bitflip = (read64_le(reinterpret_cast<const std::byte*>(secret + 8)) ^ 
                           read64_le(reinterpret_cast<const std::byte*>(secret + 16))) - seed;
        return xxh3_avalanche(data64 ^ bitflip);
    }
    
    // Process 9-16 bytes
    [[nodiscard]] inline uint64_t xxh3_len_9to16(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint64_t bitflip_lo = (read64_le(reinterpret_cast<const std::byte*>(secret + 24)) ^ 
                              read64_le(reinterpret_cast<const std::byte*>(secret + 32))) + seed;
        uint64_t bitflip_hi = (read64_le(reinterpret_cast<const std::byte*>(secret + 40)) ^ 
                              read64_le(reinterpret_cast<const std::byte*>(secret + 48))) - seed;
        uint64_t data_lo = read64_le(data) ^ bitflip_lo;
        uint64_t data_hi = read64_le(data + len - 8) ^ bitflip_hi;
        auto [lo, hi] = mul128(data_lo, data_hi);
        return xxh3_avalanche(lo ^ hi ^ len);
    }
    
    // Process 17-128 bytes
    [[nodiscard]] inline uint64_t xxh3_len_17to128(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint64_t acc = len * PRIME64_1;
        
        if (len > 32) {
            if (len > 64) {
                if (len > 96) {
                    acc += xxh3_mix16(data + 48, secret + 96, seed);
                    acc += xxh3_mix16(data + len - 64, secret + 112, seed);
                }
                acc += xxh3_mix16(data + 32, secret + 64, seed);
                acc += xxh3_mix16(data + len - 48, secret + 80, seed);
            }
            acc += xxh3_mix16(data + 16, secret + 32, seed);
            acc += xxh3_mix16(data + len - 32, secret + 48, seed);
        }
        acc += xxh3_mix16(data, secret, seed);
        acc += xxh3_mix16(data + len - 16, secret + 16, seed);
        
        return xxh3_avalanche(acc);
    }
    
    // Process 129-240 bytes
    [[nodiscard]] inline uint64_t xxh3_len_129to240(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint64_t acc = len * PRIME64_1;
        size_t nb_rounds = len / 16;
        
        for (size_t i = 0; i < 8; ++i) {
            acc += xxh3_mix16(data + 16 * i, secret + 16 * i, seed);
        }
        acc = xxh3_avalanche(acc);
        
        for (size_t i = 8; i < nb_rounds; ++i) {
            acc += xxh3_mix16(data + 16 * i, secret + 16 * (i - 8) + 3, seed);
        }
        
        acc += xxh3_mix16(data + len - 16, secret + 119, seed);
        
        return xxh3_avalanche(acc);
    }
}

// xxHash3 64-bit implementation
uint64_t xxhash3_64::hash(std::span<const std::byte> data, uint64_t seed) noexcept {
    const std::byte* ptr = data.data();
    size_t len = data.size();
    
    if (len <= 16) {
        if (len > 8) {
            return xxh3_len_9to16(ptr, len, kSecret, seed);
        } else if (len >= 4) {
            return xxh3_len_4to8(ptr, len, kSecret, seed);
        } else if (len > 0) {
            return xxh3_len_1to3(ptr, len, kSecret, seed);
        } else {
            return 0x2D06800538D394C2ULL;  // xxHash3 64-bit value for empty input
        }
    } else if (len <= 128) {
        return xxh3_len_17to128(ptr, len, kSecret, seed);
    } else if (len <= 240) {
        return xxh3_len_129to240(ptr, len, kSecret, seed);
    }
    
    // Long input (> 240 bytes)
    hasher h(seed);
    h.update(data);
    return h.finalize();
}

xxhash3_64::hasher::hasher(uint64_t seed) noexcept 
    : buffer_size_(0), total_len_(0), seed_(seed) {
    reset(seed);
}

void xxhash3_64::hasher::reset(uint64_t seed) noexcept {
    seed_ = seed;
    buffer_size_ = 0;
    total_len_ = 0;
    
    // Initialize accumulators
    acc_[0] = PRIME64_3;
    acc_[1] = PRIME64_1;
    acc_[2] = PRIME64_2;
    acc_[3] = PRIME64_4;
    acc_[4] = PRIME64_5;
    acc_[5] = PRIME64_3;
    acc_[6] = PRIME64_1;
    acc_[7] = PRIME64_2;
}

xxhash3_64::hasher& xxhash3_64::hasher::update(std::span<const std::byte> data) noexcept {
    const std::byte* ptr = data.data();
    size_t len = data.size();
    total_len_ += len;
    
    // Handle buffered data
    if (buffer_size_ + len < BUFFER_SIZE) {
        std::memcpy(buffer_.data() + buffer_size_, ptr, len);
        buffer_size_ += len;
        return *this;
    }
    
    // Process buffered data
    if (buffer_size_ > 0) {
        size_t to_fill = BUFFER_SIZE - buffer_size_;
        std::memcpy(buffer_.data() + buffer_size_, ptr, to_fill);
        
        // Process full buffer
        for (size_t i = 0; i < ACC_NB; ++i) {
            size_t offset = i * 32;
            uint64_t data_val = read64_le(buffer_.data() + offset);
            uint64_t key_val = read64_le(reinterpret_cast<const std::byte*>(kSecret + offset));
            acc_[i] += data_val * key_val;
            acc_[i] = std::rotl(acc_[i], 31);
        }
        
        ptr += to_fill;
        len -= to_fill;
        buffer_size_ = 0;
    }
    
    // Process full blocks
    while (len >= BUFFER_SIZE) {
        for (size_t i = 0; i < ACC_NB; ++i) {
            size_t offset = i * 32;
            uint64_t data_val = read64_le(ptr + offset);
            uint64_t key_val = read64_le(reinterpret_cast<const std::byte*>(kSecret + offset));
            acc_[i] += data_val * key_val;
            acc_[i] = std::rotl(acc_[i], 31);
        }
        ptr += BUFFER_SIZE;
        len -= BUFFER_SIZE;
    }
    
    // Buffer remaining data
    if (len > 0) {
        std::memcpy(buffer_.data(), ptr, len);
        buffer_size_ = len;
    }
    
    return *this;
}

uint64_t xxhash3_64::hasher::finalize() noexcept {
    // For simplicity, process any remaining buffered data
    if (total_len_ <= 240) {
        // Use one-shot hash for small inputs
        return hash(std::span<const std::byte>(buffer_.data(), buffer_size_), seed_);
    }
    
    // Merge accumulators
    uint64_t result = total_len_ * PRIME64_1;
    for (size_t i = 0; i < ACC_NB; ++i) {
        result += acc_[i];
    }
    
    // Process remaining buffer
    if (buffer_size_ > 0) {
        size_t nb_rounds = buffer_size_ / 16;
        for (size_t i = 0; i < nb_rounds; ++i) {
            result += xxh3_mix16(buffer_.data() + 16 * i, kSecret + 16 * i, seed_);
        }
        if (buffer_size_ & 15) {
            result += xxh3_mix16(buffer_.data() + buffer_size_ - 16, kSecret + 119, seed_);
        }
    }
    
    return xxh3_avalanche(result);
}

// xxHash3 128-bit implementation
xxhash3_128::hash128 xxhash3_128::hash(std::span<const std::byte> data, uint64_t seed) noexcept {
    [[maybe_unused]] const std::byte* ptr = data.data();
    [[maybe_unused]] size_t len = data.size();
    
    // For 128-bit variant, we compute two 64-bit hashes with different seeds
    uint64_t low = xxhash3_64::hash(data, seed);
    uint64_t high = xxhash3_64::hash(data, seed + PRIME64_2);
    
    return {low, high};
}

xxhash3_128::hasher::hasher(uint64_t seed) noexcept 
    : buffer_size_(0), total_len_(0), seed_(seed) {
    reset(seed);
}

void xxhash3_128::hasher::reset(uint64_t seed) noexcept {
    seed_ = seed;
    buffer_size_ = 0;
    total_len_ = 0;
    
    // Initialize accumulators (same as 64-bit version)
    acc_[0] = PRIME64_3;
    acc_[1] = PRIME64_1;
    acc_[2] = PRIME64_2;
    acc_[3] = PRIME64_4;
    acc_[4] = PRIME64_5;
    acc_[5] = PRIME64_3;
    acc_[6] = PRIME64_1;
    acc_[7] = PRIME64_2;
}

xxhash3_128::hasher& xxhash3_128::hasher::update(std::span<const std::byte> data) noexcept {
    // Implementation is identical to 64-bit version for update
    const std::byte* ptr = data.data();
    size_t len = data.size();
    total_len_ += len;
    
    // Handle buffered data
    if (buffer_size_ + len < BUFFER_SIZE) {
        std::memcpy(buffer_.data() + buffer_size_, ptr, len);
        buffer_size_ += len;
        return *this;
    }
    
    // Process buffered data
    if (buffer_size_ > 0) {
        size_t to_fill = BUFFER_SIZE - buffer_size_;
        std::memcpy(buffer_.data() + buffer_size_, ptr, to_fill);
        
        // Process full buffer
        for (size_t i = 0; i < ACC_NB; ++i) {
            size_t offset = i * 32;
            uint64_t data_val = read64_le(buffer_.data() + offset);
            uint64_t key_val = read64_le(reinterpret_cast<const std::byte*>(kSecret + offset));
            acc_[i] += data_val * key_val;
            acc_[i] = std::rotl(acc_[i], 31);
        }
        
        ptr += to_fill;
        len -= to_fill;
        buffer_size_ = 0;
    }
    
    // Process full blocks
    while (len >= BUFFER_SIZE) {
        for (size_t i = 0; i < ACC_NB; ++i) {
            size_t offset = i * 32;
            uint64_t data_val = read64_le(ptr + offset);
            uint64_t key_val = read64_le(reinterpret_cast<const std::byte*>(kSecret + offset));
            acc_[i] += data_val * key_val;
            acc_[i] = std::rotl(acc_[i], 31);
        }
        ptr += BUFFER_SIZE;
        len -= BUFFER_SIZE;
    }
    
    // Buffer remaining data
    if (len > 0) {
        std::memcpy(buffer_.data(), ptr, len);
        buffer_size_ = len;
    }
    
    return *this;
}

xxhash3_128::hash128 xxhash3_128::hasher::finalize() noexcept {
    // For 128-bit, we need to produce two different 64-bit values
    if (total_len_ <= 240) {
        // Use one-shot hash for small inputs
        return hash(std::span<const std::byte>(buffer_.data(), buffer_size_), seed_);
    }
    
    // Merge accumulators for low 64 bits
    uint64_t low = total_len_ * PRIME64_1;
    for (size_t i = 0; i < ACC_NB; ++i) {
        low += acc_[i];
    }
    
    // Merge accumulators for high 64 bits with different mixing
    uint64_t high = total_len_ * PRIME64_2;
    for (size_t i = 0; i < ACC_NB; ++i) {
        high += std::rotl(acc_[i], 7);
    }
    
    // Process remaining buffer
    if (buffer_size_ > 0) {
        size_t nb_rounds = buffer_size_ / 16;
        for (size_t i = 0; i < nb_rounds; ++i) {
            uint64_t mix = xxh3_mix16(buffer_.data() + 16 * i, kSecret + 16 * i, seed_);
            low += mix;
            high += std::rotl(mix, 23);
        }
        if (buffer_size_ & 15) {
            uint64_t mix = xxh3_mix16(buffer_.data() + buffer_size_ - 16, kSecret + 119, seed_);
            low += mix;
            high += std::rotl(mix, 41);
        }
    }
    
    return {xxh3_avalanche(low), xxh3_avalanche(high)};
}

// xxHash3 32-bit specific helpers
namespace {
    // xxHash3 32-bit avalanche
    [[nodiscard]] inline uint32_t xxh32_avalanche(uint32_t h32) noexcept {
        h32 ^= h32 >> 15;
        h32 *= PRIME32_2;
        h32 ^= h32 >> 13;
        h32 *= PRIME32_3;
        h32 ^= h32 >> 16;
        return h32;
    }
    
    // Process 1-3 bytes for 32-bit
    [[nodiscard]] inline uint32_t xxh3_32_len_1to3(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint8_t c1 = static_cast<uint8_t>(data[0]);
        uint8_t c2 = static_cast<uint8_t>(data[len >> 1]);
        uint8_t c3 = static_cast<uint8_t>(data[len - 1]);
        uint32_t combined = ((uint32_t)c1 << 16) | ((uint32_t)c2 << 24) | 
                           ((uint32_t)c3 << 0) | ((uint32_t)len << 8);
        uint32_t bitflip = static_cast<uint32_t>(read32_le(reinterpret_cast<const std::byte*>(secret)) ^ seed);
        return xxh32_avalanche(combined ^ bitflip);
    }
    
    // Process 4-8 bytes for 32-bit
    [[nodiscard]] inline uint32_t xxh3_32_len_4to8(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint32_t data32_1 = read32_le(data);
        uint32_t data32_2 = read32_le(data + len - 4);
        uint32_t bitflip = static_cast<uint32_t>(read32_le(reinterpret_cast<const std::byte*>(secret + 8)) ^ seed);
        return xxh32_avalanche((data32_1 + data32_2) ^ bitflip);
    }
    
    // Process 9-16 bytes for 32-bit
    [[nodiscard]] inline uint32_t xxh3_32_len_9to16(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint64_t bitflip_lo = (read64_le(reinterpret_cast<const std::byte*>(secret + 24)) ^ 
                              read64_le(reinterpret_cast<const std::byte*>(secret + 32))) + seed;
        uint64_t data_lo = read64_le(data) ^ bitflip_lo;
        uint64_t data_hi = read64_le(data + len - 8);
        
        // Mix to 32-bit more efficiently
        uint32_t mix = static_cast<uint32_t>(data_lo) + static_cast<uint32_t>(data_lo >> 32) +
                       static_cast<uint32_t>(data_hi) + static_cast<uint32_t>(data_hi >> 32) +
                       static_cast<uint32_t>(len);
        return xxh32_avalanche(mix);
    }
}

// xxHash3 24-bit specific helpers
namespace {
    // 24-bit specific primes for better distribution in 24-bit space
    // Based on golden ratio like other xxHash primes, with good bit distribution
    constexpr uint32_t PRIME24_1 = 10368881U;  // 0x9E3771 - near 2^24/φ, 58.3% ones
    constexpr uint32_t PRIME24_2 = 10368899U;  // 0x9E3783 - near 2^24/φ, 54.2% ones
    
    // xxHash3 24-bit avalanche - tuned for 24-bit output
    [[nodiscard]] inline uint32_t xxh24_avalanche(uint32_t h) noexcept {
        h &= 0xFFFFFF;  // Ensure we're in 24-bit range
        h ^= h >> 10;
        h *= PRIME24_1;
        h &= 0xFFFFFF;  // Keep in 24-bit range after multiply
        h ^= h >> 12;
        h *= PRIME24_2;
        h &= 0xFFFFFF;  // Keep in 24-bit range after multiply
        h ^= h >> 14;
        return h;
    }
    
    // Process 1-3 bytes for 24-bit
    [[nodiscard]] inline uint32_t xxh3_24_len_1to3(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint8_t c1 = static_cast<uint8_t>(data[0]);
        uint8_t c2 = static_cast<uint8_t>(data[len >> 1]);
        uint8_t c3 = static_cast<uint8_t>(data[len - 1]);
        // Pack into 24 bits directly
        uint32_t combined = (static_cast<uint32_t>(c1) << 16) | 
                           (static_cast<uint32_t>(c2) << 8) | 
                           static_cast<uint32_t>(c3);
        uint32_t bitflip = static_cast<uint32_t>(
            read32_le(reinterpret_cast<const std::byte*>(secret)) ^ seed) & 0xFFFFFF;
        return xxh24_avalanche(combined ^ bitflip ^ static_cast<uint32_t>(len));
    }
    
    // Process 4-8 bytes for 24-bit
    [[nodiscard]] inline uint32_t xxh3_24_len_4to8(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint32_t data32_1 = read32_le(data);
        uint32_t data32_2 = read32_le(data + len - 4);
        
        // Use multiplication for better mixing (like the 64-bit version)
        uint64_t data64 = static_cast<uint64_t>(data32_1) + (static_cast<uint64_t>(data32_2) << 24);
        uint32_t bitflip = static_cast<uint32_t>(
            read32_le(reinterpret_cast<const std::byte*>(secret + 8)) ^ seed);
        
        // Mix with multiplication
        uint64_t mixed = data64 * PRIME24_1;
        uint32_t result = static_cast<uint32_t>(mixed ^ (mixed >> 32) ^ bitflip);
        
        return xxh24_avalanche(result & 0xFFFFFF);
    }
    
    // Process 9-16 bytes for 24-bit
    [[nodiscard]] inline uint32_t xxh3_24_len_9to16(
        const std::byte* data,
        size_t len,
        const uint8_t* secret,
        uint64_t seed
    ) noexcept {
        uint64_t data_lo = read64_le(data);
        uint64_t data_hi = read64_le(data + len - 8);
        
        // Better mixing for 24-bit output - use multiplication to spread bits
        uint64_t bitflip = read64_le(reinterpret_cast<const std::byte*>(secret + 24)) ^ 
                          read64_le(reinterpret_cast<const std::byte*>(secret + 32)) ^ seed;
        
        // Mix with multiplication to ensure good distribution
        uint64_t mixed = (data_lo ^ bitflip) * PRIME64_1;
        mixed ^= (data_hi ^ std::rotl(bitflip, 23)) * PRIME64_2;
        mixed ^= mixed >> 37;
        mixed *= PRIME64_3;
        
        // Fold down to 24 bits
        uint32_t result = static_cast<uint32_t>(mixed) ^ static_cast<uint32_t>(mixed >> 32);
        result = (result ^ static_cast<uint32_t>(len)) * PRIME24_1;
        
        return xxh24_avalanche(result & 0xFFFFFF);
    }
}

// xxHash3 24-bit implementation
uint32_t xxhash3_24::hash(std::span<const std::byte> data, uint64_t seed) noexcept {
    const std::byte* ptr = data.data();
    size_t len = data.size();
    
    // Handle small inputs with optimized 24-bit paths
    if (len <= 16) {
        if (len > 8) {
            return xxh3_24_len_9to16(ptr, len, kSecret, seed);
        } else if (len >= 4) {
            return xxh3_24_len_4to8(ptr, len, kSecret, seed);
        } else if (len > 0) {
            return xxh3_24_len_1to3(ptr, len, kSecret, seed);
        } else {
            // Empty input - derive from 64-bit empty hash
            return 0xD394C2;  // Lower 24 bits of 64-bit empty hash
        }
    }
    
    // For medium inputs, use specialized 24-bit mixing
    if (len <= 128) {
        uint64_t acc = len * PRIME64_1;
        
        // Process in chunks optimized for 24-bit output
        const std::byte* end = ptr + len;
        
        if (len > 32) {
            acc += xxh3_mix16(ptr, kSecret, seed);
            acc += xxh3_mix16(ptr + 16, kSecret + 32, seed);
            ptr += 32;
            
            while (ptr + 16 <= end - 16) {
                acc += xxh3_mix16(ptr, kSecret + ((ptr - data.data()) & 0x1F), seed);
                ptr += 16;
            }
        }
        
        // Final blocks
        if (ptr < end - 16) {
            acc += xxh3_mix16(ptr, kSecret + 64, seed);
        }
        acc += xxh3_mix16(end - 16, kSecret + 96, seed);
        
        // Mix down to 24 bits
        acc = xxh3_avalanche(acc);
        uint32_t result = static_cast<uint32_t>(acc) ^ static_cast<uint32_t>(acc >> 32);
        return xxh24_avalanche(result);
    }
    
    // For large inputs, use 64-bit processing then fold to 24 bits
    uint64_t hash64 = xxhash3_64::hash(data, seed);
    
    // Fold 64 bits to 24 bits with good distribution
    uint32_t fold = static_cast<uint32_t>(hash64) ^ static_cast<uint32_t>(hash64 >> 32);
    fold ^= static_cast<uint32_t>(hash64 >> 24);  // Extra mixing for middle bits
    return xxh24_avalanche(fold);
}

// xxHash3 32-bit implementation
uint32_t xxhash3_32::hash(std::span<const std::byte> data, uint64_t seed) noexcept {
    const std::byte* ptr = data.data();
    size_t len = data.size();
    
    // Handle small inputs with optimized 32-bit paths
    if (len <= 16) {
        if (len > 8) {
            return xxh3_32_len_9to16(ptr, len, kSecret, seed);
        } else if (len >= 4) {
            return xxh3_32_len_4to8(ptr, len, kSecret, seed);
        } else if (len > 0) {
            return xxh3_32_len_1to3(ptr, len, kSecret, seed);
        } else {
            // Empty input - use lower 32 bits of 64-bit empty hash
            return 0x38D394C2U;
        }
    }
    
    // For medium inputs, use a simplified but quality-preserving approach
    if (len <= 128) {
        // Use 64-bit processing but return 32-bit result
        // This ensures good avalanche properties
        uint64_t acc = len * PRIME64_1;
        
        if (len > 32) {
            if (len > 64) {
                if (len > 96) {
                    acc += xxh3_mix16(ptr + 48, kSecret + 96, seed);
                    acc += xxh3_mix16(ptr + len - 64, kSecret + 112, seed);
                }
                acc += xxh3_mix16(ptr + 32, kSecret + 64, seed);
                acc += xxh3_mix16(ptr + len - 48, kSecret + 80, seed);
            }
            acc += xxh3_mix16(ptr + 16, kSecret + 32, seed);
            acc += xxh3_mix16(ptr + len - 32, kSecret + 48, seed);
        }
        acc += xxh3_mix16(ptr, kSecret, seed);
        acc += xxh3_mix16(ptr + len - 16, kSecret + 16, seed);
        
        // Final mix and convert to 32-bit
        acc = xxh3_avalanche(acc);
        return static_cast<uint32_t>(acc ^ (acc >> 32));
    }
    
    // For very large inputs, fall back to truncating 64-bit hash
    // as the performance benefit of 32-bit specific code diminishes
    return static_cast<uint32_t>(xxhash3_64::hash(data, seed));
}

} // namespace psyfer