/**
 * @file aes_arm64.cpp
 * @brief ARM64 hardware accelerated AES implementation
 */

#include <psyfer.hpp>
#include <cstring>

#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO
#include <arm_neon.h>
#endif
#endif

namespace psyfer {

#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO

/**
 * @brief ARM64 key expansion helper
 */
static inline uint8x16_t aes_key_expand_assist(uint8x16_t key, uint8x16_t keygened) {
    key = vextq_u8(key, key, 12);
    key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 12));
    key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 12));
    key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 12));
    return veorq_u8(key, keygened);
}

/**
 * @brief AES key generation assist function
 */
static inline uint8x16_t aes_keygen(uint8x16_t key, uint8_t rcon) {
    uint8x16_t a = vaeseq_u8(key, vmovq_n_u8(0));
    // Shuffle bytes: equivalent to libsodium's __builtin_shufflevector
    uint8x16_t b = vqtbl1q_u8(a, (uint8x16_t){4, 1, 14, 11, 1, 14, 11, 4, 12, 9, 6, 3, 9, 6, 3, 12});
    // Add round constant
    uint32x4_t rc = vdupq_n_u32((uint32_t)rcon << 24);
    return vreinterpretq_u8_u32(veorq_u32(vreinterpretq_u32_u8(b), rc));
}

/**
 * @brief AES-256 key expansion using ARM crypto extensions
 */
void aes256_key_expansion_arm64(const uint8_t* key, uint8x16_t* round_keys) {
    uint8x16_t t1 = vld1q_u8(key);
    uint8x16_t t2 = vld1q_u8(key + 16);
    uint8x16_t s;
    size_t i = 0;
    
    // Macro for key expansion rounds
    #define EXPAND_KEY_256_ROUND1(RC) \
        round_keys[i++] = t1; \
        s = aes_keygen(t2, RC); \
        t1 = veorq_u8(t1, vextq_u8(vdupq_n_u8(0), t1, 12)); \
        t1 = veorq_u8(t1, vextq_u8(vdupq_n_u8(0), t1, 8)); \
        t1 = veorq_u8(t1, vextq_u8(vdupq_n_u8(0), t1, 4)); \
        t1 = veorq_u8(t1, vdupq_laneq_u8(s, 12));
        
    #define EXPAND_KEY_256_ROUND2() \
        round_keys[i++] = t2; \
        s = vqtbl1q_u8(vaeseq_u8(t1, vmovq_n_u8(0)), (uint8x16_t){0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}); \
        t2 = veorq_u8(t2, vextq_u8(vdupq_n_u8(0), t2, 12)); \
        t2 = veorq_u8(t2, vextq_u8(vdupq_n_u8(0), t2, 8)); \
        t2 = veorq_u8(t2, vextq_u8(vdupq_n_u8(0), t2, 4)); \
        t2 = veorq_u8(t2, s);
    
    EXPAND_KEY_256_ROUND1(0x01);
    EXPAND_KEY_256_ROUND2();
    EXPAND_KEY_256_ROUND1(0x02);
    EXPAND_KEY_256_ROUND2();
    EXPAND_KEY_256_ROUND1(0x04);
    EXPAND_KEY_256_ROUND2();
    EXPAND_KEY_256_ROUND1(0x08);
    EXPAND_KEY_256_ROUND2();
    EXPAND_KEY_256_ROUND1(0x10);
    EXPAND_KEY_256_ROUND2();
    EXPAND_KEY_256_ROUND1(0x20);
    EXPAND_KEY_256_ROUND2();
    EXPAND_KEY_256_ROUND1(0x40);
    round_keys[i++] = t1;
    
    #undef EXPAND_KEY_256_ROUND1
    #undef EXPAND_KEY_256_ROUND2
}

/**
 * @brief Encrypt a single block using ARM crypto extensions
 */
void aes256_encrypt_block_arm64(const uint8x16_t* round_keys, uint8_t* block) {
    uint8x16_t state = vld1q_u8(block);
    
    // Initial round
    state = veorq_u8(state, round_keys[0]);
    
    // Main rounds
    state = vaeseq_u8(state, round_keys[1]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[2]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[3]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[4]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[5]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[6]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[7]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[8]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[9]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[10]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[11]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[12]);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, round_keys[13]);
    
    // Final round (no MixColumns)
    state = vaeseq_u8(state, vdupq_n_u8(0));
    state = veorq_u8(state, round_keys[14]);
    
    vst1q_u8(block, state);
}

/**
 * @brief Decrypt a single block using ARM crypto extensions
 */
void aes256_decrypt_block_arm64(const uint8x16_t* round_keys, uint8_t* block) {
    uint8x16_t state = vld1q_u8(block);
    
    // Prepare inverse round keys
    uint8x16_t inv_keys[15];
    inv_keys[0] = round_keys[14];
    inv_keys[14] = round_keys[0];
    
    for (int i = 1; i < 14; ++i) {
        inv_keys[i] = vaesimcq_u8(round_keys[14 - i]);
    }
    
    // Initial round
    state = veorq_u8(state, inv_keys[0]);
    
    // Main rounds
    state = vaesdq_u8(state, inv_keys[1]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[2]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[3]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[4]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[5]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[6]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[7]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[8]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[9]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[10]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[11]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[12]);
    state = vaesimcq_u8(state);
    state = vaesdq_u8(state, inv_keys[13]);
    
    // Final round
    state = vaesdq_u8(state, vdupq_n_u8(0));
    state = veorq_u8(state, inv_keys[14]);
    
    vst1q_u8(block, state);
}

/**
 * @brief Check if ARM crypto extensions are available
 */
bool aes_arm64_available() {
    // On ARM64, we check at compile time with __ARM_FEATURE_CRYPTO
    // Runtime detection would require reading system registers
    return true;
}

#endif // __ARM_FEATURE_CRYPTO
#endif // __aarch64__

} // namespace psyfer