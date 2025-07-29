/**
 * @file aes256_ni.cpp
 * @brief AES-NI hardware accelerated implementation
 */

#include <psyfer/crypto/aes256.hpp>

#ifdef __AES__
#include <wmmintrin.h>  // AES-NI intrinsics
#include <emmintrin.h>  // SSE2
#include <smmintrin.h>  // SSE4.1
#endif

namespace psyfer::crypto {

#ifdef __AES__

/**
 * @brief AES-NI key expansion helper
 */
static inline __m128i aes_key_expand_assist(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

/**
 * @brief AES-256 key expansion using AES-NI
 */
void aes256_key_expansion_ni(const uint8_t* key, __m128i* round_keys) {
    round_keys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    round_keys[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));
    
    round_keys[2] = aes_key_expand_assist(round_keys[0], _mm_aeskeygenassist_si128(round_keys[1], 0x01));
    round_keys[3] = aes_key_expand_assist(round_keys[1], _mm_aeskeygenassist_si128(round_keys[2], 0x00));
    
    round_keys[4] = aes_key_expand_assist(round_keys[2], _mm_aeskeygenassist_si128(round_keys[3], 0x02));
    round_keys[5] = aes_key_expand_assist(round_keys[3], _mm_aeskeygenassist_si128(round_keys[4], 0x00));
    
    round_keys[6] = aes_key_expand_assist(round_keys[4], _mm_aeskeygenassist_si128(round_keys[5], 0x04));
    round_keys[7] = aes_key_expand_assist(round_keys[5], _mm_aeskeygenassist_si128(round_keys[6], 0x00));
    
    round_keys[8] = aes_key_expand_assist(round_keys[6], _mm_aeskeygenassist_si128(round_keys[7], 0x08));
    round_keys[9] = aes_key_expand_assist(round_keys[7], _mm_aeskeygenassist_si128(round_keys[8], 0x00));
    
    round_keys[10] = aes_key_expand_assist(round_keys[8], _mm_aeskeygenassist_si128(round_keys[9], 0x10));
    round_keys[11] = aes_key_expand_assist(round_keys[9], _mm_aeskeygenassist_si128(round_keys[10], 0x00));
    
    round_keys[12] = aes_key_expand_assist(round_keys[10], _mm_aeskeygenassist_si128(round_keys[11], 0x20));
    round_keys[13] = aes_key_expand_assist(round_keys[11], _mm_aeskeygenassist_si128(round_keys[12], 0x00));
    
    round_keys[14] = aes_key_expand_assist(round_keys[12], _mm_aeskeygenassist_si128(round_keys[13], 0x40));
}

/**
 * @brief Encrypt a single block using AES-NI
 */
void aes256_encrypt_block_ni(const __m128i* round_keys, uint8_t* block) {
    __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block));
    
    // Initial round
    state = _mm_xor_si128(state, round_keys[0]);
    
    // Main rounds
    state = _mm_aesenc_si128(state, round_keys[1]);
    state = _mm_aesenc_si128(state, round_keys[2]);
    state = _mm_aesenc_si128(state, round_keys[3]);
    state = _mm_aesenc_si128(state, round_keys[4]);
    state = _mm_aesenc_si128(state, round_keys[5]);
    state = _mm_aesenc_si128(state, round_keys[6]);
    state = _mm_aesenc_si128(state, round_keys[7]);
    state = _mm_aesenc_si128(state, round_keys[8]);
    state = _mm_aesenc_si128(state, round_keys[9]);
    state = _mm_aesenc_si128(state, round_keys[10]);
    state = _mm_aesenc_si128(state, round_keys[11]);
    state = _mm_aesenc_si128(state, round_keys[12]);
    state = _mm_aesenc_si128(state, round_keys[13]);
    
    // Final round
    state = _mm_aesenclast_si128(state, round_keys[14]);
    
    _mm_storeu_si128(reinterpret_cast<__m128i*>(block), state);
}

/**
 * @brief Decrypt a single block using AES-NI
 */
void aes256_decrypt_block_ni(const __m128i* round_keys, uint8_t* block) {
    __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block));
    
    // Prepare decryption round keys (inverse mix columns)
    __m128i dec_keys[15];
    dec_keys[0] = round_keys[14];
    dec_keys[14] = round_keys[0];
    
    for (int i = 1; i < 14; ++i) {
        dec_keys[i] = _mm_aesimc_si128(round_keys[14 - i]);
    }
    
    // Initial round
    state = _mm_xor_si128(state, dec_keys[0]);
    
    // Main rounds
    state = _mm_aesdec_si128(state, dec_keys[1]);
    state = _mm_aesdec_si128(state, dec_keys[2]);
    state = _mm_aesdec_si128(state, dec_keys[3]);
    state = _mm_aesdec_si128(state, dec_keys[4]);
    state = _mm_aesdec_si128(state, dec_keys[5]);
    state = _mm_aesdec_si128(state, dec_keys[6]);
    state = _mm_aesdec_si128(state, dec_keys[7]);
    state = _mm_aesdec_si128(state, dec_keys[8]);
    state = _mm_aesdec_si128(state, dec_keys[9]);
    state = _mm_aesdec_si128(state, dec_keys[10]);
    state = _mm_aesdec_si128(state, dec_keys[11]);
    state = _mm_aesdec_si128(state, dec_keys[12]);
    state = _mm_aesdec_si128(state, dec_keys[13]);
    
    // Final round
    state = _mm_aesdeclast_si128(state, dec_keys[14]);
    
    _mm_storeu_si128(reinterpret_cast<__m128i*>(block), state);
}

/**
 * @brief GCM multiplication using PCLMULQDQ
 */
#ifdef __PCLMUL__
static void gcm_mult_pclmul(__m128i* x, const __m128i h) {
    // Reverse bits for GCM's bit order
    const __m128i bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i a = _mm_shuffle_epi8(*x, bswap_mask);
    __m128i b = _mm_shuffle_epi8(h, bswap_mask);
    
    // Carry-less multiplication
    __m128i tmp0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i tmp1 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i tmp2 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i tmp3 = _mm_clmulepi64_si128(a, b, 0x11);
    
    // Combine results
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    tmp2 = _mm_slli_si128(tmp1, 8);
    tmp1 = _mm_srli_si128(tmp1, 8);
    tmp0 = _mm_xor_si128(tmp0, tmp2);
    tmp3 = _mm_xor_si128(tmp3, tmp1);
    
    // Reduction
    __m128i tmp4 = _mm_srli_epi32(tmp0, 31);
    __m128i tmp5 = _mm_srli_epi32(tmp3, 31);
    tmp0 = _mm_slli_epi32(tmp0, 1);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    
    __m128i tmp6 = _mm_srli_si128(tmp4, 12);
    tmp5 = _mm_slli_si128(tmp5, 4);
    tmp4 = _mm_slli_si128(tmp4, 4);
    tmp0 = _mm_or_si128(tmp0, tmp4);
    tmp3 = _mm_or_si128(tmp3, tmp5);
    tmp3 = _mm_or_si128(tmp3, tmp6);
    
    // Final reduction
    tmp4 = _mm_slli_epi32(tmp0, 31);
    tmp5 = _mm_slli_epi32(tmp0, 30);
    tmp6 = _mm_slli_epi32(tmp0, 25);
    
    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp4 = _mm_xor_si128(tmp4, tmp6);
    tmp5 = _mm_srli_si128(tmp4, 4);
    tmp4 = _mm_slli_si128(tmp4, 12);
    tmp0 = _mm_xor_si128(tmp0, tmp4);
    
    tmp1 = _mm_srli_epi32(tmp0, 1);
    tmp2 = _mm_srli_epi32(tmp0, 2);
    tmp3 = _mm_srli_epi32(tmp0, 7);
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    tmp1 = _mm_xor_si128(tmp1, tmp5);
    tmp0 = _mm_xor_si128(tmp0, tmp1);
    tmp3 = _mm_xor_si128(tmp3, tmp0);
    
    *x = _mm_shuffle_epi8(tmp3, bswap_mask);
}
#endif

/**
 * @brief Check if AES-NI is available at runtime
 */
bool aes_ni_available() {
    #ifdef __AES__
    // Check CPUID for AES-NI support
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

/**
 * @brief Hardware-accelerated AES-256 implementation
 */
class aes256_ni {
private:
    alignas(16) __m128i round_keys[15];
    
public:
    explicit aes256_ni(std::span<const std::byte, 32> key) noexcept {
        aes256_key_expansion_ni(reinterpret_cast<const uint8_t*>(key.data()), round_keys);
    }
    
    void encrypt_block(std::span<std::byte, 16> block) noexcept {
        aes256_encrypt_block_ni(round_keys, reinterpret_cast<uint8_t*>(block.data()));
    }
    
    void decrypt_block(std::span<std::byte, 16> block) noexcept {
        aes256_decrypt_block_ni(round_keys, reinterpret_cast<uint8_t*>(block.data()));
    }
};

#endif // __AES__

} // namespace psyfer::crypto