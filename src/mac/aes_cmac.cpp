/**
 * @file aes_cmac.cpp
 * @brief AES-CMAC implementation
 */

#include <psyfer.hpp>
#include <cstring>

namespace psyfer {

// Constants for CMAC
namespace {
    constexpr std::byte RB_128 = std::byte{0x87};  // R_128 = 0^120 || 10000111
    
    /**
     * @brief XOR two blocks
     */
    void xor_blocks(
        std::span<std::byte, 16> result,
        std::span<const std::byte, 16> a,
        std::span<const std::byte, 16> b
    ) noexcept {
        for (size_t i = 0; i < 16; ++i) {
            result[i] = a[i] ^ b[i];
        }
    }
}

// AES-128 cipher implementation
template<>
struct aes_cmac<16>::cipher_impl {
    aes128 cipher;
    
    explicit cipher_impl(std::span<const std::byte, 16> key) noexcept 
        : cipher(key) {}
    
    void encrypt_block(std::span<std::byte, 16> block) noexcept {
        cipher.encrypt_block(block);
    }
};

// AES-256 cipher implementation
template<>
struct aes_cmac<32>::cipher_impl {
    aes256 cipher;
    
    explicit cipher_impl(std::span<const std::byte, 32> key) noexcept 
        : cipher(key) {}
    
    void encrypt_block(std::span<std::byte, 16> block) noexcept {
        cipher.encrypt_block(block);
    }
};

// Constructor for AES-CMAC-128
template<>
aes_cmac<16>::aes_cmac(std::span<const std::byte, 16> key) noexcept 
    : cipher(std::make_unique<cipher_impl>(key)) {
    generate_subkeys();
    reset();
}

// Destructor for AES-CMAC-128
template<>
aes_cmac<16>::~aes_cmac() noexcept = default;

// Constructor for AES-CMAC-256
template<>
aes_cmac<32>::aes_cmac(std::span<const std::byte, 32> key) noexcept 
    : cipher(std::make_unique<cipher_impl>(key)) {
    generate_subkeys();
    reset();
}

// Destructor for AES-CMAC-256
template<>
aes_cmac<32>::~aes_cmac() noexcept = default;

// Common implementation for both variants
template<size_t KeySize>
void aes_cmac<KeySize>::generate_subkeys() noexcept {
    // Step 1: L = AES(K, 0^128)
    std::array<std::byte, BLOCK_SIZE> L{};
    cipher->encrypt_block(L);
    
    // Step 2: K1 = L << 1 [possibly XOR with RB]
    std::memcpy(k1.data(), L.data(), BLOCK_SIZE);
    bool msb = (static_cast<uint8_t>(L[0]) & 0x80) != 0;
    left_shift_one(k1);
    if (msb) {
        k1[15] ^= RB_128;
    }
    
    // Step 3: K2 = K1 << 1 [possibly XOR with RB]
    std::memcpy(k2.data(), k1.data(), BLOCK_SIZE);
    msb = (static_cast<uint8_t>(k1[0]) & 0x80) != 0;
    left_shift_one(k2);
    if (msb) {
        k2[15] ^= RB_128;
    }
}

template<size_t KeySize>
void aes_cmac<KeySize>::left_shift_one(std::span<std::byte, BLOCK_SIZE> data) noexcept {
    uint8_t overflow = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t current = static_cast<uint8_t>(data[i]);
        data[i] = static_cast<std::byte>((current << 1) | overflow);
        overflow = (current & 0x80) ? 1 : 0;
    }
}

template<size_t KeySize>
void aes_cmac<KeySize>::reset() noexcept {
    // Clear state
    secure_clear(state.data(), state.size());
    secure_clear(buffer.data(), buffer.size());
    buffer_pos = 0;
}

template<size_t KeySize>
void aes_cmac<KeySize>::process_block(std::span<const std::byte, BLOCK_SIZE> block) noexcept {
    // XOR with state
    xor_blocks(state, state, block);
    // Encrypt
    cipher->encrypt_block(state);
}

template<size_t KeySize>
void aes_cmac<KeySize>::update(std::span<const std::byte> data) noexcept {
    const std::byte* ptr = data.data();
    size_t remaining = data.size();
    
    // Handle buffered data
    if (buffer_pos > 0) {
        size_t to_copy = std::min(remaining, BLOCK_SIZE - buffer_pos);
        std::memcpy(buffer.data() + buffer_pos, ptr, to_copy);
        buffer_pos += to_copy;
        ptr += to_copy;
        remaining -= to_copy;
        
        if (buffer_pos == BLOCK_SIZE) {
            process_block(buffer);
            buffer_pos = 0;
        }
    }
    
    // Process complete blocks (but keep last block in buffer)
    while (remaining > BLOCK_SIZE) {
        process_block(std::span<const std::byte, BLOCK_SIZE>(ptr, BLOCK_SIZE));
        ptr += BLOCK_SIZE;
        remaining -= BLOCK_SIZE;
    }
    
    // Buffer remaining data
    if (remaining > 0) {
        std::memcpy(buffer.data() + buffer_pos, ptr, remaining);
        buffer_pos += remaining;
    }
}

template<size_t KeySize>
void aes_cmac<KeySize>::finalize(std::span<std::byte, MAC_SIZE> mac) noexcept {
    std::array<std::byte, BLOCK_SIZE> last_block{};
    
    if (buffer_pos == BLOCK_SIZE) {
        // Complete block - XOR with K1
        xor_blocks(last_block, buffer, k1);
    } else {
        // Partial block - pad and XOR with K2
        std::memcpy(last_block.data(), buffer.data(), buffer_pos);
        last_block[buffer_pos] = std::byte{0x80};  // Padding: 10000000...
        // Rest is already zero
        xor_blocks(last_block, last_block, k2);
    }
    
    // Final processing
    process_block(last_block);
    
    // Output MAC
    std::memcpy(mac.data(), state.data(), MAC_SIZE);
    
    // Reset for next use
    reset();
}

template<size_t KeySize>
void aes_cmac<KeySize>::compute(
    std::span<const std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<std::byte, MAC_SIZE> mac
) noexcept {
    aes_cmac<KeySize> cmac(key);
    cmac.update(data);
    cmac.finalize(mac);
}

template<size_t KeySize>
bool aes_cmac<KeySize>::verify(
    std::span<const std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, MAC_SIZE> mac
) noexcept {
    std::array<std::byte, MAC_SIZE> computed_mac;
    compute(data, key, computed_mac);
    
    // Constant-time comparison
    return secure_compare(computed_mac.data(), mac.data(), MAC_SIZE);
}
// Explicit template instantiations
template class aes_cmac<16>;
template class aes_cmac<32>;

} // namespace psyfer
