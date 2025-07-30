/**
 * @file aes128.cpp
 * @brief AES-128 implementation with hardware acceleration
 */

#include <psyfer.hpp>
#include <cstring>

namespace psyfer::crypto {

// AES S-box (same as AES-256)
constexpr uint8_t sbox[256] = {
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

aes128::aes128(std::span<const std::byte, KEY_SIZE> key) noexcept {
    use_hw_acceleration = aes_ni_available();
    
    #ifdef __APPLE__
    // On macOS, use CommonCrypto
    use_hw_acceleration = true;
    // CommonCrypto doesn't need explicit key expansion
    std::memcpy(round_keys.data(), key.data(), KEY_SIZE);
    #else
    key_expansion(key);
    #endif
}

void aes128::encrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    #ifdef __APPLE__
    // Use CommonCrypto on macOS
    aes128_encrypt_block_cc(
        reinterpret_cast<const uint8_t*>(round_keys.data()),
        reinterpret_cast<uint8_t*>(block.data())
    );
    #elif defined(__AES__) && (defined(__x86_64__) || defined(__i386__))
    if (use_hw_acceleration) {
        aes128_encrypt_block_ni(
            reinterpret_cast<const uint8_t*>(round_keys.data()),
            reinterpret_cast<uint8_t*>(block.data())
        );
    } else {
        encrypt_block_sw(block);
    }
    #else
    encrypt_block_sw(block);
    #endif
}

void aes128::decrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    #ifdef __APPLE__
    // Use CommonCrypto on macOS
    aes128_decrypt_block_cc(
        reinterpret_cast<const uint8_t*>(round_keys.data()),
        reinterpret_cast<uint8_t*>(block.data())
    );
    #elif defined(__AES__) && (defined(__x86_64__) || defined(__i386__))
    if (use_hw_acceleration) {
        aes128_decrypt_block_ni(
            reinterpret_cast<const uint8_t*>(round_keys.data()),
            reinterpret_cast<uint8_t*>(block.data())
        );
    } else {
        decrypt_block_sw(block);
    }
    #else
    decrypt_block_sw(block);
    #endif
}

void aes128::key_expansion(std::span<const std::byte, KEY_SIZE> key) noexcept {
    #if defined(__AES__) && (defined(__x86_64__) || defined(__i386__))
    if (use_hw_acceleration) {
        aes128_key_expansion_ni(
            reinterpret_cast<const uint8_t*>(key.data()),
            reinterpret_cast<uint8_t*>(round_keys.data())
        );
        return;
    }
    #endif
    
    // Software key expansion
    constexpr uint8_t rcon[] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };
    
    // Copy initial key
    std::memcpy(round_keys.data(), key.data(), KEY_SIZE);
    
    // Generate round keys
    uint8_t* w = reinterpret_cast<uint8_t*>(round_keys.data());
    
    for (int i = 4; i < 44; ++i) {  // 44 words for AES-128
        uint32_t temp;
        std::memcpy(&temp, w + (i-1)*4, 4);
        
        if (i % 4 == 0) {
            // RotWord
            temp = ((temp & 0xFF) << 24) | (temp >> 8);
            
            // SubWord
            uint8_t* bytes = reinterpret_cast<uint8_t*>(&temp);
            for (int j = 0; j < 4; ++j) {
                bytes[j] = sbox[bytes[j]];
            }
            
            // XOR with Rcon
            bytes[0] ^= rcon[i/4 - 1];
        }
        
        uint32_t wi_4;
        std::memcpy(&wi_4, w + (i-4)*4, 4);
        uint32_t wi = wi_4 ^ temp;
        std::memcpy(w + i*4, &wi, 4);
    }
}

void aes128::encrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    uint8_t state[16];
    std::memcpy(state, block.data(), 16);
    
    // Initial round key addition
    for (int i = 0; i < 16; ++i) {
        state[i] ^= static_cast<uint8_t>(round_keys[i]);
    }
    
    // Main rounds
    for (size_t round = 1; round <= ROUNDS; ++round) {
        // SubBytes
        for (int i = 0; i < 16; ++i) {
            state[i] = sbox[state[i]];
        }
        
        // ShiftRows
        uint8_t temp;
        // Row 1: shift left by 1
        temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
        
        // Row 2: shift left by 2
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;
        
        // Row 3: shift left by 3
        temp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = temp;
        
        // MixColumns (not in final round)
        if (round < ROUNDS) {
            for (int col = 0; col < 4; ++col) {
                int idx = col * 4;
                uint8_t a[4];
                uint8_t b[4];
                for (int i = 0; i < 4; ++i) {
                    a[i] = state[idx + i];
                    b[i] = (a[i] << 1) ^ ((a[i] & 0x80) ? 0x1b : 0);
                }
                state[idx] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
                state[idx + 1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
                state[idx + 2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
                state[idx + 3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
            }
        }
        
        // AddRoundKey
        for (int i = 0; i < 16; ++i) {
            state[i] ^= static_cast<uint8_t>(round_keys[round * 16 + i]);
        }
    }
    
    std::memcpy(block.data(), state, 16);
}

// Inverse S-box for decryption
static constexpr uint8_t inv_sbox[256] = {
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

// Helper functions for decryption
static void add_round_key(uint8_t state[16], const uint8_t* round_key) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = inv_sbox[state[i]];
    }
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;  // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

static void inv_mix_columns(uint8_t state[16]) {
    // Multiply by inverse matrix
    // [0x0e, 0x0b, 0x0d, 0x09]
    // [0x09, 0x0e, 0x0b, 0x0d]
    // [0x0d, 0x09, 0x0e, 0x0b]
    // [0x0b, 0x0d, 0x09, 0x0e]
    for (int col = 0; col < 4; ++col) {
        int idx = col * 4;
        uint8_t s0 = state[idx];
        uint8_t s1 = state[idx + 1];
        uint8_t s2 = state[idx + 2];
        uint8_t s3 = state[idx + 3];
        
        state[idx]     = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        state[idx + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        state[idx + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        state[idx + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
}

void aes128::decrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept {
    // AES-128 software decryption implementation
    uint8_t state[16];
    std::memcpy(state, block.data(), 16);
    
    // Inverse cipher
    add_round_key(state, reinterpret_cast<const uint8_t*>(round_keys.data()) + 10 * 16);
    
    for (int round = 9; round >= 1; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, reinterpret_cast<const uint8_t*>(round_keys.data()) + round * 16);
        inv_mix_columns(state);
    }
    
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, reinterpret_cast<const uint8_t*>(round_keys.data()));
    
    std::memcpy(block.data(), state, 16);
}

#ifdef __APPLE__
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonCrypto.h>

// CommonCrypto implementation
bool aes128_commoncrypto_available() noexcept {
    return true;
}

void aes128_encrypt_block_cc(const uint8_t* key, uint8_t* block) noexcept {
    size_t bytes_encrypted = 0;
    [[maybe_unused]] CCCryptorStatus status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES128,
        kCCOptionECBMode,  // ECB mode for single block
        key, kCCKeySizeAES128,
        nullptr,  // No IV for ECB
        block, kCCBlockSizeAES128,
        block, kCCBlockSizeAES128,
        &bytes_encrypted
    );
}

void aes128_decrypt_block_cc(const uint8_t* key, uint8_t* block) noexcept {
    size_t bytes_decrypted = 0;
    [[maybe_unused]] CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES128,
        kCCOptionECBMode,  // ECB mode for single block
        key, kCCKeySizeAES128,
        nullptr,  // No IV for ECB
        block, kCCBlockSizeAES128,
        block, kCCBlockSizeAES128,
        &bytes_decrypted
    );
}
#endif

} // namespace psyfer::crypto