/**
 * @file aes128_ni.cpp
 * @brief AES-128 implementation using AES-NI instructions
 */

#include <psyfer/crypto/aes128.hpp>

#if defined(__AES__) && (defined(__x86_64__) || defined(__i386__))

#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

namespace psyfer::crypto {

namespace {
    /**
     * @brief AES-NI key expansion assist
     */
    inline __m128i aes128_keyexpand_assist(__m128i temp1, __m128i temp2) {
        __m128i temp3;
        temp2 = _mm_shuffle_epi32(temp2, 0xff);
        temp3 = _mm_slli_si128(temp1, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp1 = _mm_xor_si128(temp1, temp2);
        return temp1;
    }
}

void aes128_key_expansion_ni(const uint8_t* key, uint8_t* round_keys) noexcept {
    __m128i temp1, temp2;
    __m128i* key_schedule = reinterpret_cast<__m128i*>(round_keys);
    
    // Load the key
    temp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    key_schedule[0] = temp1;
    
    // Round 1
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[1] = temp1;
    
    // Round 2
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[2] = temp1;
    
    // Round 3
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[3] = temp1;
    
    // Round 4
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[4] = temp1;
    
    // Round 5
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[5] = temp1;
    
    // Round 6
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[6] = temp1;
    
    // Round 7
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[7] = temp1;
    
    // Round 8
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[8] = temp1;
    
    // Round 9
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1B);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[9] = temp1;
    
    // Round 10
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = aes128_keyexpand_assist(temp1, temp2);
    key_schedule[10] = temp1;
}

void aes128_encrypt_block_ni(const uint8_t* round_keys, uint8_t* block) noexcept {
    __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block));
    const __m128i* key_schedule = reinterpret_cast<const __m128i*>(round_keys);
    
    // Initial round
    m = _mm_xor_si128(m, key_schedule[0]);
    
    // 9 main rounds
    m = _mm_aesenc_si128(m, key_schedule[1]);
    m = _mm_aesenc_si128(m, key_schedule[2]);
    m = _mm_aesenc_si128(m, key_schedule[3]);
    m = _mm_aesenc_si128(m, key_schedule[4]);
    m = _mm_aesenc_si128(m, key_schedule[5]);
    m = _mm_aesenc_si128(m, key_schedule[6]);
    m = _mm_aesenc_si128(m, key_schedule[7]);
    m = _mm_aesenc_si128(m, key_schedule[8]);
    m = _mm_aesenc_si128(m, key_schedule[9]);
    
    // Final round
    m = _mm_aesenclast_si128(m, key_schedule[10]);
    
    _mm_storeu_si128(reinterpret_cast<__m128i*>(block), m);
}

void aes128_decrypt_block_ni(const uint8_t* round_keys, uint8_t* block) noexcept {
    __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block));
    const __m128i* key_schedule = reinterpret_cast<const __m128i*>(round_keys);
    
    // For decryption, we need inverse key schedule
    // For now, we'll skip this as CMAC only needs encryption
}

} // namespace psyfer::crypto

#endif // __AES__ && (__x86_64__ || __i386__)