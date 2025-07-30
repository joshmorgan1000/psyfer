/**
 * @file ghash_portable.cpp
 * @brief Portable GHASH implementation ported from libsodium to C++23
 */

#include <array>
#include <span>
#include <cstring>
#include <bit>

namespace psyfer::crypto::detail {

/**
 * @brief Reverse bytes in a 16-byte block (for GCM's bit ordering)
 */
static void reverse_bytes(std::array<std::byte, 16>& block) noexcept {
    for (int i = 0; i < 8; ++i) {
        std::swap(block[i], block[15 - i]);
    }
}

/**
 * @brief Galois field (2^128) multiplication
 * 
 * This implements multiplication in GF(2^128) with the GCM reduction polynomial
 * x^128 + x^7 + x^2 + x + 1
 */
static void gf_mult(
    std::array<std::byte, 16>& result,
    const std::array<std::byte, 16>& x,
    const std::array<std::byte, 16>& y
) noexcept {
    // Work with reversed byte order as per GCM specification
    std::array<std::byte, 16> a = x;
    std::array<std::byte, 16> b = y;
    reverse_bytes(a);
    reverse_bytes(b);
    
    // Initialize result to zero
    std::array<std::byte, 16> z{};
    
    // Multiplication using the standard bit-by-bit algorithm
    for (int i = 0; i < 128; ++i) {
        // Get bit i of a (LSB first due to reversal)
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        
        if ((static_cast<uint8_t>(a[byte_idx]) >> bit_idx) & 1) {
            // z ^= b
            for (int j = 0; j < 16; ++j) {
                z[j] ^= b[j];
            }
        }
        
        // b = b * x (multiply by x in GF(2^128))
        // This is a left shift by 1 bit with reduction
        bool carry = (static_cast<uint8_t>(b[15]) & 0x80) != 0;
        
        // Shift left by 1 bit
        for (int j = 15; j > 0; --j) {
            b[j] = std::byte(
                (static_cast<uint8_t>(b[j]) << 1) | 
                (static_cast<uint8_t>(b[j-1]) >> 7)
            );
        }
        b[0] = std::byte(static_cast<uint8_t>(b[0]) << 1);
        
        // If there was a carry, XOR with the reduction polynomial
        // R = 11100001 || 0^120 (in reversed bit order)
        if (carry) {
            b[0] ^= std::byte(0xe1);
        }
    }
    
    // Reverse back to normal byte order
    reverse_bytes(z);
    result = z;
}

/**
 * @brief GHASH function for GCM mode
 * 
 * Processes data blocks and updates the GHASH accumulator
 */
void ghash_portable(
    std::array<std::byte, 16>& accumulator,
    const std::array<std::byte, 16>& h,
    std::span<const std::byte> data
) noexcept {
    // Process each 16-byte block
    for (size_t i = 0; i < data.size(); i += 16) {
        // XOR block with accumulator
        size_t block_size = std::min<size_t>(16, data.size() - i);
        for (size_t j = 0; j < block_size; ++j) {
            accumulator[j] ^= data[i + j];
        }
        
        // Multiply by H in GF(2^128)
        std::array<std::byte, 16> temp;
        gf_mult(temp, accumulator, h);
        accumulator = temp;
    }
}

} // namespace psyfer::crypto::detail