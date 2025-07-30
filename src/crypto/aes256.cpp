/**
 * @file aes256.cpp
 * @brief Implementation of AES-256 encryption with GCM mode
 */

#include <psyfer.hpp>
#include <algorithm>
#include <bit>
#include <cstring>

#ifdef __AES__
#include <wmmintrin.h>  // AES-NI intrinsics
#include <emmintrin.h>  // SSE2
#include <smmintrin.h>  // SSE4.1
#endif

#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO
#include <arm_neon.h>
#endif
#endif

namespace psyfer::crypto {

// Forward declarations for hardware acceleration

#ifdef __AES__
extern void aes256_key_expansion_ni(const uint8_t* key, __m128i* round_keys);
extern void aes256_encrypt_block_ni(const __m128i* round_keys, uint8_t* block);
extern void aes256_decrypt_block_ni(const __m128i* round_keys, uint8_t* block);
#endif

#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO
extern void aes256_key_expansion_arm64(const uint8_t* key, uint8x16_t* round_keys);
extern void aes256_encrypt_block_arm64(const uint8x16_t* round_keys, uint8_t* block);
extern void aes256_decrypt_block_arm64(const uint8x16_t* round_keys, uint8_t* block);
extern bool aes_arm64_available();
#endif
#endif

// Static method to check hardware support
bool aes256::hardware_available() noexcept {
    return aes_ni_available();
}

// Check for AES-NI support
bool aes_ni_available() noexcept {
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    // ARM64 crypto extensions - if compiled with support, assume available
    // Runtime detection would require reading system registers which may be privileged
    return true;
    #elif defined(__AES__)
    // Check CPUID for AES-NI support on x86_64
    int cpu_info[4];
    __asm__ volatile(
        "cpuid"
        : "=a"(cpu_info[0]), "=b"(cpu_info[1]), "=c"(cpu_info[2]), "=d"(cpu_info[3])
        : "a"(1), "c"(0)
    );
    return (cpu_info[2] & (1 << 25)) != 0;  // Check AES bit
    #else
    return false;
    #endif
}

// AES S-box (substitution box)
static constexpr std::array<uint8_t, 256> sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box for decryption
static constexpr std::array<uint8_t, 256> inv_sbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants for key expansion
static constexpr std::array<uint32_t, 10> rcon = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

// Helper functions
static uint32_t sub_word(uint32_t word) noexcept {
    return (sbox[(word >> 24) & 0xff] << 24) |
           (sbox[(word >> 16) & 0xff] << 16) |
           (sbox[(word >> 8) & 0xff] << 8) |
           (sbox[word & 0xff]);
}

static uint32_t rot_word(uint32_t word) noexcept {
    return (word << 8) | (word >> 24);
}

// Galois field multiplication by 2
static uint8_t gmul2(uint8_t a) noexcept {
    return (a << 1) ^ ((a & 0x80) ? 0x1b : 0);
}

// General Galois field multiplication
static uint8_t gmul(uint8_t a, uint8_t b) noexcept {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

aes256::aes256(std::span<const std::byte, KEY_SIZE> key) noexcept {
    use_hw_acceleration = aes_ni_available();
    // Note: We have a software fallback implementation, but for production use
    // we strongly recommend hardware acceleration for both security and performance.
    // The software implementation passes all test vectors but is significantly slower.
    key_expansion(key);
}

void aes256::key_expansion(std::span<const std::byte, KEY_SIZE> key) noexcept {
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if (use_hw_acceleration) {
        aes256_key_expansion_arm64(reinterpret_cast<const uint8_t*>(key.data()), 
                                  reinterpret_cast<uint8x16_t*>(round_keys.data()));
        return;
    }
    #elif defined(__AES__)
    if (use_hw_acceleration) {
        aes256_key_expansion_ni(reinterpret_cast<const uint8_t*>(key.data()), 
                               reinterpret_cast<__m128i*>(round_keys.data()));
        return;
    }
    #endif
    
    // Software implementation
    // Copy initial key
    std::memcpy(round_keys.data(), key.data(), KEY_SIZE);
    
    uint32_t* w = reinterpret_cast<uint32_t*>(round_keys.data());
    const int Nk = 8; // Number of 32-bit words in key (256 bits / 32)
    const int Nb = 4; // Number of 32-bit words in block
    const int Nr = ROUNDS;
    
    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[(i / Nk) - 1];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
}

void aes256::encrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if (use_hw_acceleration) {
        aes256_encrypt_block_arm64(reinterpret_cast<const uint8x16_t*>(round_keys.data()),
                                  reinterpret_cast<uint8_t*>(block.data()));
        return;
    }
    #elif defined(__AES__)
    if (use_hw_acceleration) {
        aes256_encrypt_block_ni(reinterpret_cast<const __m128i*>(round_keys.data()),
                               reinterpret_cast<uint8_t*>(block.data()));
        return;
    }
    #endif
    encrypt_block_sw(block);
}

void aes256::encrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    std::array<uint8_t, 16> state;
    std::memcpy(state.data(), block.data(), 16);
    
    const uint8_t* round_key = reinterpret_cast<const uint8_t*>(round_keys.data());
    
    // Initial round key addition
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
    
    // Main rounds
    for (size_t round = 1; round < ROUNDS; ++round) {
        // SubBytes
        for (int i = 0; i < 16; ++i) {
            state[i] = sbox[state[i]];
        }
        
        // ShiftRows
        uint8_t temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
        
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;
        
        temp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = temp;
        
        // MixColumns
        for (int col = 0; col < 4; ++col) {
            int idx = col * 4;
            uint8_t a0 = state[idx];
            uint8_t a1 = state[idx + 1];
            uint8_t a2 = state[idx + 2];
            uint8_t a3 = state[idx + 3];
            
            state[idx] = gmul2(a0) ^ gmul(a1, 3) ^ a2 ^ a3;
            state[idx + 1] = a0 ^ gmul2(a1) ^ gmul(a2, 3) ^ a3;
            state[idx + 2] = a0 ^ a1 ^ gmul2(a2) ^ gmul(a3, 3);
            state[idx + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul2(a3);
        }
        
        // AddRoundKey
        round_key = reinterpret_cast<const uint8_t*>(round_keys.data()) + round * 16;
        for (int i = 0; i < 16; ++i) {
            state[i] ^= round_key[i];
        }
    }
    
    // Final round (no MixColumns)
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
    
    // ShiftRows
    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
    
    // AddRoundKey
    round_key = reinterpret_cast<const uint8_t*>(round_keys.data()) + ROUNDS * 16;
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
    
    std::memcpy(block.data(), state.data(), 16);
}

void aes256::decrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if (use_hw_acceleration) {
        aes256_decrypt_block_arm64(reinterpret_cast<const uint8x16_t*>(round_keys.data()),
                                  reinterpret_cast<uint8_t*>(block.data()));
        return;
    }
    #elif defined(__AES__)
    if (use_hw_acceleration) {
        aes256_decrypt_block_ni(reinterpret_cast<const __m128i*>(round_keys.data()),
                               reinterpret_cast<uint8_t*>(block.data()));
        return;
    }
    #endif
    decrypt_block_sw(block);
}

void aes256::decrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    std::array<uint8_t, 16> state;
    std::memcpy(state.data(), block.data(), 16);
    
    const uint8_t* round_key = reinterpret_cast<const uint8_t*>(round_keys.data()) + ROUNDS * 16;
    
    // Initial round key addition
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
    
    // Main rounds (in reverse)
    for (size_t round = ROUNDS - 1; round > 0; --round) {
        // InvShiftRows
        uint8_t temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;
        
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;
        
        temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
        
        // InvSubBytes
        for (int i = 0; i < 16; ++i) {
            state[i] = inv_sbox[state[i]];
        }
        
        // AddRoundKey
        round_key = reinterpret_cast<const uint8_t*>(round_keys.data()) + round * 16;
        for (int i = 0; i < 16; ++i) {
            state[i] ^= round_key[i];
        }
        
        // InvMixColumns
        for (int col = 0; col < 4; ++col) {
            int idx = col * 4;
            uint8_t a0 = state[idx];
            uint8_t a1 = state[idx + 1];
            uint8_t a2 = state[idx + 2];
            uint8_t a3 = state[idx + 3];
            
            state[idx] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
            state[idx + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
            state[idx + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
            state[idx + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
        }
    }
    
    // Final round
    // InvShiftRows
    uint8_t temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
    
    // InvSubBytes
    for (int i = 0; i < 16; ++i) {
        state[i] = inv_sbox[state[i]];
    }
    
    // AddRoundKey
    round_key = reinterpret_cast<const uint8_t*>(round_keys.data());
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
    
    std::memcpy(block.data(), state.data(), 16);
}

// GCM implementation

// Forward declaration of portable GHASH
namespace detail {
    void ghash_portable(
        std::array<std::byte, 16>& accumulator,
        const std::array<std::byte, 16>& h,
        std::span<const std::byte> data
    ) noexcept;
}

void aes256_gcm::ghash(
    std::span<std::byte, 16> output,
    std::span<const std::byte, 16> h,
    std::span<const std::byte> data
) noexcept {
    // Use the portable GHASH implementation
    std::array<std::byte, 16> accumulator;
    std::memcpy(accumulator.data(), output.data(), 16);
    
    std::array<std::byte, 16> h_array;
    std::memcpy(h_array.data(), h.data(), 16);
    
    detail::ghash_portable(accumulator, h_array, data);
    
    std::memcpy(output.data(), accumulator.data(), 16);
}

void aes256_gcm::increment_counter(std::span<std::byte, 16> counter) noexcept {
    // Increment the last 4 bytes (32-bit counter)
    for (int i = 15; i >= 12; --i) {
        counter[i] = static_cast<std::byte>(static_cast<uint8_t>(counter[i]) + 1);
        if (counter[i] != std::byte(0)) {
            break;
        }
    }
}

#ifdef HAVE_OPENSSL
// Use OpenSSL implementation for AES-256-GCM since our GHASH has padding issues
#include <openssl/evp.h>
#include <memory>

struct EVPCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
};

using EVPCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPCipherCtxDeleter>;

std::error_code aes256_gcm::encrypt(
    std::span<std::byte> data,
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<std::byte> tag,
    std::span<const std::byte> aad
) noexcept {
    // Validate parameters
    if (key.size() != KEY_SIZE) {
        return make_error_code(error_code::invalid_key_size);
    }
    if (nonce.size() != NONCE_SIZE) {
        return make_error_code(error_code::invalid_nonce_size);
    }
    if (tag.size() != TAG_SIZE) {
        return make_error_code(error_code::invalid_tag_size);
    }

    // Create cipher context
    EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return make_error_code(error_code::encryption_failed);
    }

    // Initialize encryption with AES-256-GCM
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return make_error_code(error_code::encryption_failed);
    }

    // Set IV length (nonce for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 
                           static_cast<int>(nonce.size()), nullptr) != 1) {
        return make_error_code(error_code::encryption_failed);
    }

    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                          reinterpret_cast<const unsigned char*>(key.data()),
                          reinterpret_cast<const unsigned char*>(nonce.data())) != 1) {
        return make_error_code(error_code::encryption_failed);
    }

    // Process AAD
    if (!aad.empty()) {
        int outlen;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen,
                             reinterpret_cast<const unsigned char*>(aad.data()),
                             static_cast<int>(aad.size())) != 1) {
            return make_error_code(error_code::encryption_failed);
        }
    }

    // Encrypt data in-place
    int outlen;
    int total_len = 0;
    if (EVP_EncryptUpdate(ctx.get(),
                         reinterpret_cast<unsigned char*>(data.data()), &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         static_cast<int>(data.size())) != 1) {
        return make_error_code(error_code::encryption_failed);
    }
    total_len += outlen;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(),
                           reinterpret_cast<unsigned char*>(data.data()) + total_len,
                           &outlen) != 1) {
        return make_error_code(error_code::encryption_failed);
    }

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16,
                           reinterpret_cast<unsigned char*>(tag.data())) != 1) {
        return make_error_code(error_code::encryption_failed);
    }

    return {};
}
#else
// Original implementation with GHASH padding issue
std::error_code aes256_gcm::encrypt(
    std::span<std::byte> data,
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<std::byte> tag,
    std::span<const std::byte> aad
) noexcept {
    if (key.size() != KEY_SIZE) {
        return make_error_code(error_code::invalid_key_size);
    }
    if (nonce.size() != NONCE_SIZE) {
        return make_error_code(error_code::invalid_nonce_size);
    }
    if (tag.size() != TAG_SIZE) {
        return make_error_code(error_code::invalid_tag_size);
    }
    
    aes256 cipher(std::span<const std::byte, KEY_SIZE>{key.data(), KEY_SIZE});
    
    // Prepare IV (96-bit nonce + 32-bit counter starting at 2)
    // Note: Counter value 1 is reserved for computing the final authentication tag
    std::array<std::byte, 16> counter{};
    std::memcpy(counter.data(), nonce.data(), 12);
    counter[15] = std::byte(2);
    
    // Generate authentication key H = AES(K, 0)
    std::array<std::byte, 16> h{};
    cipher.encrypt_block(h);
    
    // Encrypt data using CTR mode
    // Counter starts at 2 for first data block (counter=1 is reserved for tag)
    for (size_t i = 0; i < data.size(); i += 16) {
        std::array<std::byte, 16> keystream = counter;
        cipher.encrypt_block(keystream);
        
        size_t block_size = std::min<size_t>(16, data.size() - i);
        for (size_t j = 0; j < block_size; ++j) {
            data[i + j] ^= keystream[j];
        }
        
        increment_counter(counter);
    }
    
    // Calculate authentication tag
    std::array<std::byte, 16> ghash_output{};
    
    // Process AAD
    if (!aad.empty()) {
        ghash(ghash_output, h, aad);
        /* TODO: Fix GHASH padding between AAD and ciphertext
         * 
         * PROBLEM DESCRIPTION:
         * The GCM specification requires specific padding between different data sections:
         * 1. AAD is processed first
         * 2. If AAD length is not a multiple of 16, pad with zeros to 16-byte boundary
         * 3. Then process ciphertext
         * 4. If ciphertext length is not a multiple of 16, pad with zeros to 16-byte boundary
         * 5. Finally process the length block
         *
         * CURRENT ISSUE:
         * Our ghash_portable() function handles partial blocks internally by only XORing
         * the actual data bytes with the accumulator. However, GCM requires that we
         * explicitly process the padding zeros through GHASH to maintain proper state
         * between AAD and ciphertext sections.
         *
         * WHAT'S HAPPENING:
         * - Empty plaintext test PASSES because it only processes the length block
         * - Any test with data FAILS because the GHASH state is wrong
         *
         * ATTEMPTED FIXES:
         * 1. Tried adding explicit padding by calling ghash() with zero blocks - this
         *    processes the padding as separate blocks which is incorrect
         * 2. Removed padding entirely - this is also wrong as GCM requires the padding
         *
         * CORRECT SOLUTION:
         * We need to modify how ghash_portable() works to handle GCM's specific
         * padding requirements. The padding zeros should be part of the same GHASH
         * computation, not separate blocks. This likely requires passing additional
         * context about whether we're at a section boundary.
         *
         * REFERENCE:
         * See NIST SP 800-38D Section 7.1 and libsodium's implementation in
         * crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c
         */
    }
    
    // Process ciphertext
    ghash(ghash_output, h, data);
    /* TODO: Fix GHASH padding after ciphertext
     * Same issue as above - ciphertext must be padded to 16-byte boundary
     * before processing the length block, maintaining GHASH state properly.
     */
    
    // Add length block
    std::array<std::byte, 16> lengths{};
    uint64_t aad_bits = aad.size() * 8;
    uint64_t data_bits = data.size() * 8;
    
    // Store lengths in big-endian (high bits first, then low bits)
    for (int i = 0; i < 8; ++i) {
        lengths[i] = std::byte((aad_bits >> (56 - i * 8)) & 0xff);
        lengths[8 + i] = std::byte((data_bits >> (56 - i * 8)) & 0xff);
    }
    ghash(ghash_output, h, lengths);
    
    // Final tag = GHASH XOR AES(K, J0)
    std::array<std::byte, 16> j0{};
    std::memcpy(j0.data(), nonce.data(), 12);
    j0[15] = std::byte(1);
    cipher.encrypt_block(j0);
    
    for (int i = 0; i < 16; ++i) {
        tag[i] = ghash_output[i] ^ j0[i];
    }
    
    return {};
}
#endif // HAVE_OPENSSL

#ifdef HAVE_OPENSSL
std::error_code aes256_gcm::decrypt(
    std::span<std::byte> data,
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> tag,
    std::span<const std::byte> aad
) noexcept {
    // Validate parameters
    if (key.size() != KEY_SIZE) {
        return make_error_code(error_code::invalid_key_size);
    }
    if (nonce.size() != NONCE_SIZE) {
        return make_error_code(error_code::invalid_nonce_size);
    }
    if (tag.size() != TAG_SIZE) {
        return make_error_code(error_code::invalid_tag_size);
    }

    // Create cipher context
    EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return make_error_code(error_code::decryption_failed);
    }

    // Initialize decryption with AES-256-GCM
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return make_error_code(error_code::decryption_failed);
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != 1) {
        return make_error_code(error_code::decryption_failed);
    }

    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                          reinterpret_cast<const unsigned char*>(key.data()),
                          reinterpret_cast<const unsigned char*>(nonce.data())) != 1) {
        return make_error_code(error_code::decryption_failed);
    }

    // Process AAD
    if (!aad.empty()) {
        int outlen;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen,
                             reinterpret_cast<const unsigned char*>(aad.data()),
                             static_cast<int>(aad.size())) != 1) {
            return make_error_code(error_code::decryption_failed);
        }
    }

    // Decrypt data in-place
    int outlen;
    int total_len = 0;
    if (EVP_DecryptUpdate(ctx.get(),
                         reinterpret_cast<unsigned char*>(data.data()), &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         static_cast<int>(data.size())) != 1) {
        return make_error_code(error_code::decryption_failed);
    }
    total_len += outlen;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                           const_cast<unsigned char*>(
                               reinterpret_cast<const unsigned char*>(tag.data()))) != 1) {
        return make_error_code(error_code::decryption_failed);
    }

    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx.get(),
                           reinterpret_cast<unsigned char*>(data.data()) + total_len,
                           &outlen) != 1) {
        // Authentication failed
        return make_error_code(error_code::authentication_failed);
    }

    return {};
}
#else
std::error_code aes256_gcm::decrypt(
    std::span<std::byte> data,
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> tag,
    std::span<const std::byte> aad
) noexcept {
    if (key.size() != KEY_SIZE) {
        return make_error_code(error_code::invalid_key_size);
    }
    if (nonce.size() != NONCE_SIZE) {
        return make_error_code(error_code::invalid_nonce_size);
    }
    if (tag.size() != TAG_SIZE) {
        return make_error_code(error_code::invalid_tag_size);
    }
    
    aes256 cipher(std::span<const std::byte, KEY_SIZE>{key.data(), KEY_SIZE});
    
    // First, verify the tag
    std::array<std::byte, 16> computed_tag{};
    
    // Prepare IV (96-bit nonce + 32-bit counter starting at 2) 
    // Note: Counter value 1 is reserved for computing the final authentication tag
    std::array<std::byte, 16> counter{};
    std::memcpy(counter.data(), nonce.data(), 12);
    counter[15] = std::byte(2);
    
    // Generate authentication key H
    std::array<std::byte, 16> h{};
    cipher.encrypt_block(h);
    
    // Calculate expected tag
    std::array<std::byte, 16> ghash_output{};
    
    // Process AAD
    if (!aad.empty()) {
        ghash(ghash_output, h, aad);
        // TODO: Fix GHASH padding between AAD and ciphertext
        // Same issue as in encrypt() - see comments there
    }
    
    // Process ciphertext
    ghash(ghash_output, h, data);
    // TODO: Fix GHASH padding after ciphertext
    // Same issue as in encrypt() - see comments there
    
    // Add length block
    std::array<std::byte, 16> lengths{};
    uint64_t aad_bits = aad.size() * 8;
    uint64_t data_bits = data.size() * 8;
    
    // Store lengths in big-endian (high bits first, then low bits)
    for (int i = 0; i < 8; ++i) {
        lengths[i] = std::byte((aad_bits >> (56 - i * 8)) & 0xff);
        lengths[8 + i] = std::byte((data_bits >> (56 - i * 8)) & 0xff);
    }
    ghash(ghash_output, h, lengths);
    
    // Final tag computation
    std::array<std::byte, 16> j0{};
    std::memcpy(j0.data(), nonce.data(), 12);
    j0[15] = std::byte(1);
    cipher.encrypt_block(j0);
    
    for (int i = 0; i < 16; ++i) {
        computed_tag[i] = ghash_output[i] ^ j0[i];
    }
    
    // Constant-time comparison
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= static_cast<uint8_t>(computed_tag[i]) ^ static_cast<uint8_t>(tag[i]);
    }
    
    if (diff != 0) {
        return make_error_code(error_code::authentication_failed);
    }
    
    // Decrypt data (same as encrypt for CTR mode)
    // Counter starts at 2 for first data block (counter=1 is reserved for tag)
    for (size_t i = 0; i < data.size(); i += 16) {
        std::array<std::byte, 16> keystream = counter;
        cipher.encrypt_block(keystream);
        
        size_t block_size = std::min<size_t>(16, data.size() - i);
        for (size_t j = 0; j < block_size; ++j) {
            data[i + j] ^= keystream[j];
        }
        
        increment_counter(counter);
    }
    
    return {};
}
#endif // HAVE_OPENSSL

std::error_code aes256_gcm::encrypt_oneshot(
    std::span<std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, NONCE_SIZE> nonce,
    std::span<std::byte, TAG_SIZE> tag,
    std::span<const std::byte> aad
) noexcept {
    aes256_gcm gcm;
    return gcm.encrypt(data, key, nonce, tag, aad);
}

std::error_code aes256_gcm::decrypt_oneshot(
    std::span<std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, NONCE_SIZE> nonce,
    std::span<const std::byte, TAG_SIZE> tag,
    std::span<const std::byte> aad
) noexcept {
    aes256_gcm gcm;
    return gcm.decrypt(data, key, nonce, tag, aad);
}

} // namespace psyfer::crypto