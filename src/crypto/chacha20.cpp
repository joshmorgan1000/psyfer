/**
 * @file chacha20.cpp
 * @brief Implementation of ChaCha20-Poly1305 AEAD
 */

#include <psyfer.hpp>
#include <cstring>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <memory>
#endif

namespace psyfer {

// ChaCha20 constants
static constexpr uint32_t CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

// ChaCha20 implementation
void chacha20::quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

void chacha20::generate_block(
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, NONCE_SIZE> nonce,
    uint32_t counter,
    std::span<std::byte, BLOCK_SIZE> output
) noexcept {
    // Initialize state
    uint32_t state[16];
    
    // Constants
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];
    
    // Key
    std::memcpy(&state[4], key.data(), 32);
    
    // Counter
    state[12] = counter;
    
    // Nonce
    std::memcpy(&state[13], nonce.data(), 12);
    
    // Working state
    uint32_t working[16];
    std::memcpy(working, state, sizeof(working));
    
    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; ++i) {
        // Column rounds
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);
        
        // Diagonal rounds
        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }
    
    // Add initial state
    for (int i = 0; i < 16; ++i) {
        working[i] += state[i];
    }
    
    // Write output
    std::memcpy(output.data(), working, BLOCK_SIZE);
}

void chacha20::crypt(
    std::span<std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, NONCE_SIZE> nonce,
    uint32_t counter
) noexcept {
    std::array<std::byte, BLOCK_SIZE> keystream;
    size_t pos = 0;
    
    while (pos < data.size()) {
        // Generate keystream block
        generate_block(key, nonce, counter++, keystream);
        
        // XOR with data
        size_t block_size = std::min(BLOCK_SIZE, data.size() - pos);
        for (size_t i = 0; i < block_size; ++i) {
            data[pos + i] ^= keystream[i];
        }
        
        pos += block_size;
    }
}

// Poly1305 implementation
void poly1305::init(std::span<const std::byte, KEY_SIZE> key) noexcept {
    // Extract r and clamp
    r_[0] = (static_cast<uint32_t>(static_cast<uint8_t>(key[0])) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[1])) << 8) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[2])) << 16) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[3])) << 24)) & 0x3ffffff;
    
    r_[1] = ((static_cast<uint32_t>(static_cast<uint8_t>(key[3])) >> 2) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[4])) << 6) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[5])) << 14) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[6])) << 22)) & 0x3ffff03;
    
    r_[2] = ((static_cast<uint32_t>(static_cast<uint8_t>(key[6])) >> 4) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[7])) << 4) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[8])) << 12) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[9])) << 20)) & 0x3ffc0ff;
    
    r_[3] = ((static_cast<uint32_t>(static_cast<uint8_t>(key[9])) >> 6) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[10])) << 2) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[11])) << 10) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[12])) << 18)) & 0x3f03fff;
    
    r_[4] = ((static_cast<uint32_t>(static_cast<uint8_t>(key[12])) >> 8) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[13])) << 0) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[14])) << 8) |
             (static_cast<uint32_t>(static_cast<uint8_t>(key[15])) << 16)) & 0x00fffff;
    
    // Extract pad
    pad_[0] = static_cast<uint32_t>(static_cast<uint8_t>(key[16])) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[17])) << 8) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[18])) << 16) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[19])) << 24);
    
    pad_[1] = static_cast<uint32_t>(static_cast<uint8_t>(key[20])) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[21])) << 8) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[22])) << 16) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[23])) << 24);
    
    pad_[2] = static_cast<uint32_t>(static_cast<uint8_t>(key[24])) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[25])) << 8) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[26])) << 16) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[27])) << 24);
    
    pad_[3] = static_cast<uint32_t>(static_cast<uint8_t>(key[28])) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[29])) << 8) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[30])) << 16) |
              (static_cast<uint32_t>(static_cast<uint8_t>(key[31])) << 24);
    
    // Clear accumulator
    h_[0] = h_[1] = h_[2] = h_[3] = h_[4] = 0;
    leftover_ = 0;
    finalized_ = false;
}

void poly1305::process_block(const uint8_t* block, bool final) noexcept {
    // Convert block to number
    uint64_t t0 = static_cast<uint64_t>(block[0]) |
                  (static_cast<uint64_t>(block[1]) << 8) |
                  (static_cast<uint64_t>(block[2]) << 16) |
                  (static_cast<uint64_t>(block[3]) << 24);
    
    uint64_t t1 = static_cast<uint64_t>(block[4]) |
                  (static_cast<uint64_t>(block[5]) << 8) |
                  (static_cast<uint64_t>(block[6]) << 16) |
                  (static_cast<uint64_t>(block[7]) << 24);
    
    uint64_t t2 = static_cast<uint64_t>(block[8]) |
                  (static_cast<uint64_t>(block[9]) << 8) |
                  (static_cast<uint64_t>(block[10]) << 16) |
                  (static_cast<uint64_t>(block[11]) << 24);
    
    uint64_t t3 = static_cast<uint64_t>(block[12]) |
                  (static_cast<uint64_t>(block[13]) << 8) |
                  (static_cast<uint64_t>(block[14]) << 16) |
                  (static_cast<uint64_t>(block[15]) << 24);
    
    // Add to accumulator
    uint64_t h0 = h_[0] + (t0 & 0x3ffffff);
    uint64_t h1 = h_[1] + ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    uint64_t h2 = h_[2] + ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    uint64_t h3 = h_[3] + ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    uint64_t h4 = h_[4] + (t3 >> 8) + (final ? 0 : (1 << 24));
    
    // Multiply by r
    uint64_t d0 = h0 * r_[0] + h1 * (5 * r_[4]) + h2 * (5 * r_[3]) + h3 * (5 * r_[2]) + h4 * (5 * r_[1]);
    uint64_t d1 = h0 * r_[1] + h1 * r_[0] + h2 * (5 * r_[4]) + h3 * (5 * r_[3]) + h4 * (5 * r_[2]);
    uint64_t d2 = h0 * r_[2] + h1 * r_[1] + h2 * r_[0] + h3 * (5 * r_[4]) + h4 * (5 * r_[3]);
    uint64_t d3 = h0 * r_[3] + h1 * r_[2] + h2 * r_[1] + h3 * r_[0] + h4 * (5 * r_[4]);
    uint64_t d4 = h0 * r_[4] + h1 * r_[3] + h2 * r_[2] + h3 * r_[1] + h4 * r_[0];
    
    // Carry propagation
    uint32_t c = static_cast<uint32_t>(d0 >> 26);
    h_[0] = static_cast<uint32_t>(d0) & 0x3ffffff;
    d1 += c;
    
    c = static_cast<uint32_t>(d1 >> 26);
    h_[1] = static_cast<uint32_t>(d1) & 0x3ffffff;
    d2 += c;
    
    c = static_cast<uint32_t>(d2 >> 26);
    h_[2] = static_cast<uint32_t>(d2) & 0x3ffffff;
    d3 += c;
    
    c = static_cast<uint32_t>(d3 >> 26);
    h_[3] = static_cast<uint32_t>(d3) & 0x3ffffff;
    d4 += c;
    
    c = static_cast<uint32_t>(d4 >> 26);
    h_[4] = static_cast<uint32_t>(d4) & 0x3ffffff;
    h_[0] += c * 5;
    
    c = h_[0] >> 26;
    h_[0] &= 0x3ffffff;
    h_[1] += c;
}

void poly1305::update(std::span<const std::byte> data) noexcept {
    if (finalized_) return;
    
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    size_t len = data.size();
    
    // Handle leftover
    if (leftover_) {
        size_t want = 16 - leftover_;
        if (want > len) want = len;
        
        std::memcpy(buffer_ + leftover_, bytes, want);
        len -= want;
        bytes += want;
        leftover_ += want;
        
        if (leftover_ < 16) return;
        
        process_block(buffer_);
        leftover_ = 0;
    }
    
    // Process full blocks
    while (len >= 16) {
        process_block(bytes);
        bytes += 16;
        len -= 16;
    }
    
    // Store leftover
    if (len) {
        std::memcpy(buffer_, bytes, len);
        leftover_ = len;
    }
}

void poly1305::finalize(std::span<std::byte, TAG_SIZE> tag) noexcept {
    if (finalized_) return;
    
    // Process final block
    if (leftover_) {
        buffer_[leftover_] = 1;
        for (size_t i = leftover_ + 1; i < 16; ++i) {
            buffer_[i] = 0;
        }
        process_block(buffer_, true);
    }
    
    // Final reduction
    uint32_t h0 = h_[0];
    uint32_t h1 = h_[1];
    uint32_t h2 = h_[2];
    uint32_t h3 = h_[3];
    uint32_t h4 = h_[4];
    
    uint32_t c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;
    
    // Compute h - p
    uint32_t g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    
    uint32_t g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    
    uint32_t g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    
    uint32_t g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    
    uint32_t g4 = h4 + c - (1 << 26);
    
    // Select h if h < p, or h - p if h >= p
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    
    // Convert to bytes and add pad
    h0 |= h1 << 26;
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);
    
    uint64_t t0 = static_cast<uint64_t>(h0) + pad_[0];
    uint64_t t1 = static_cast<uint64_t>(h1) + pad_[1] + (t0 >> 32);
    uint64_t t2 = static_cast<uint64_t>(h2) + pad_[2] + (t1 >> 32);
    uint64_t t3 = static_cast<uint64_t>(h3) + pad_[3] + (t2 >> 32);
    
    // Write tag
    tag[0] = static_cast<std::byte>(t0);
    tag[1] = static_cast<std::byte>(t0 >> 8);
    tag[2] = static_cast<std::byte>(t0 >> 16);
    tag[3] = static_cast<std::byte>(t0 >> 24);
    tag[4] = static_cast<std::byte>(t1);
    tag[5] = static_cast<std::byte>(t1 >> 8);
    tag[6] = static_cast<std::byte>(t1 >> 16);
    tag[7] = static_cast<std::byte>(t1 >> 24);
    tag[8] = static_cast<std::byte>(t2);
    tag[9] = static_cast<std::byte>(t2 >> 8);
    tag[10] = static_cast<std::byte>(t2 >> 16);
    tag[11] = static_cast<std::byte>(t2 >> 24);
    tag[12] = static_cast<std::byte>(t3);
    tag[13] = static_cast<std::byte>(t3 >> 8);
    tag[14] = static_cast<std::byte>(t3 >> 16);
    tag[15] = static_cast<std::byte>(t3 >> 24);
    
    finalized_ = true;
}

void poly1305::auth(
    std::span<const std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<std::byte, TAG_SIZE> tag
) noexcept {
    poly1305 poly;
    poly.init(key);
    poly.update(data);
    poly.finalize(tag);
}

// ChaCha20-Poly1305 implementation
void chacha20_poly1305::generate_poly_key(
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, NONCE_SIZE> nonce,
    std::span<std::byte, 32> poly_key
) noexcept {
    // Generate first ChaCha20 block with counter 0
    std::array<std::byte, 64> block;
    chacha20::generate_block(key, nonce, 0, block);
    
    // Use first 32 bytes as Poly1305 key
    std::memcpy(poly_key.data(), block.data(), 32);
}

void chacha20_poly1305::pad16(poly1305& poly, size_t len) noexcept {
    if (len % 16 != 0) {
        std::array<std::byte, 16> zeros{};
        poly.update(std::span<const std::byte>(zeros.data(), 16 - (len % 16)));
    }
}

#ifdef HAVE_OPENSSL
struct EVPCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
};

using EVPCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPCipherCtxDeleter>;

std::error_code chacha20_poly1305::encrypt(
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

    // Initialize encryption with ChaCha20-Poly1305
    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        return make_error_code(error_code::encryption_failed);
    }

    // Set IV length (nonce for ChaCha20-Poly1305)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
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
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16,
                           reinterpret_cast<unsigned char*>(tag.data())) != 1) {
        return make_error_code(error_code::encryption_failed);
    }

    return {};
}
#else
// Original implementation with Poly1305 padding issue
std::error_code chacha20_poly1305::encrypt(
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
    
    // Generate Poly1305 key
    std::array<std::byte, 32> poly_key;
    generate_poly_key(
        std::span<const std::byte, KEY_SIZE>(key.data(), KEY_SIZE),
        std::span<const std::byte, NONCE_SIZE>(nonce.data(), NONCE_SIZE),
        poly_key
    );
    
    // Encrypt data with ChaCha20 (counter starts at 1)
    chacha20::crypt(
        data,
        std::span<const std::byte, KEY_SIZE>(key.data(), KEY_SIZE),
        std::span<const std::byte, NONCE_SIZE>(nonce.data(), NONCE_SIZE),
        1
    );
    
    // Compute authentication tag
    /* TODO: Fix Poly1305 authentication
     * 
     * PROBLEM DESCRIPTION:
     * Similar to the AES-GCM GHASH issue, our Poly1305 authentication is producing
     * incorrect tags compared to the RFC 8439 test vectors.
     * 
     * CURRENT BEHAVIOR:
     * - The ChaCha20 encryption itself is correct (ciphertext matches)
     * - The Poly1305 authentication tag is wrong
     * - Expected: 1ae10b594f09e26a7e902ecbd0600691
     * - Got:      2dfcb1284cbb08be8b8e41325015526e
     *
     * LIKELY ISSUES:
     * 1. The padding between AAD and ciphertext might be incorrect
     * 2. The Poly1305 implementation might have endianness issues
     * 3. The way we're feeding data to Poly1305 might not match RFC 8439
     *
     * RFC 8439 CONSTRUCTION:
     * 1. Pad AAD to 16-byte boundary
     * 2. Process ciphertext
     * 3. Pad ciphertext to 16-byte boundary
     * 4. Append 8-byte little-endian AAD length
     * 5. Append 8-byte little-endian ciphertext length
     *
     * Our pad16() function seems correct, but the overall construction might be wrong.
     */
    poly1305 poly;
    poly.init(poly_key);
    
    // AAD
    poly.update(aad);
    pad16(poly, aad.size());
    
    // Ciphertext
    poly.update(data);
    pad16(poly, data.size());
    
    // Lengths
    uint64_t aad_len = aad.size();
    uint64_t data_len = data.size();
    std::array<std::byte, 16> lengths;
    
    for (int i = 0; i < 8; ++i) {
        lengths[i] = static_cast<std::byte>(aad_len >> (i * 8));
        lengths[8 + i] = static_cast<std::byte>(data_len >> (i * 8));
    }
    
    poly.update(lengths);
    poly.finalize(std::span<std::byte, TAG_SIZE>(tag.data(), TAG_SIZE));
    
    return {};
}
#endif // HAVE_OPENSSL

#ifdef HAVE_OPENSSL
std::error_code chacha20_poly1305::decrypt(
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

    // Initialize decryption with ChaCha20-Poly1305
    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        return make_error_code(error_code::decryption_failed);
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
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
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16,
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
// Original implementation with Poly1305 padding issue  
std::error_code chacha20_poly1305::decrypt(
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
    
    // Generate Poly1305 key
    std::array<std::byte, 32> poly_key;
    generate_poly_key(
        std::span<const std::byte, KEY_SIZE>(key.data(), KEY_SIZE),
        std::span<const std::byte, NONCE_SIZE>(nonce.data(), NONCE_SIZE),
        poly_key
    );
    
    // Compute expected tag
    poly1305 poly;
    poly.init(poly_key);
    
    // AAD
    poly.update(aad);
    pad16(poly, aad.size());
    
    // Ciphertext
    poly.update(data);
    pad16(poly, data.size());
    
    // Lengths
    uint64_t aad_len = aad.size();
    uint64_t data_len = data.size();
    std::array<std::byte, 16> lengths;
    
    for (int i = 0; i < 8; ++i) {
        lengths[i] = static_cast<std::byte>(aad_len >> (i * 8));
        lengths[8 + i] = static_cast<std::byte>(data_len >> (i * 8));
    }
    
    poly.update(lengths);
    
    std::array<std::byte, TAG_SIZE> computed_tag;
    poly.finalize(computed_tag);
    
    // Verify tag
    bool valid = true;
    for (size_t i = 0; i < TAG_SIZE; ++i) {
        valid &= (computed_tag[i] == tag[i]);
    }
    
    if (!valid) {
        return make_error_code(error_code::authentication_failed);
    }
    
    // Decrypt data
    chacha20::crypt(
        data,
        std::span<const std::byte, KEY_SIZE>(key.data(), KEY_SIZE),
        std::span<const std::byte, NONCE_SIZE>(nonce.data(), NONCE_SIZE),
        1
    );
    
    return {};
}
#endif // HAVE_OPENSSL

std::error_code chacha20_poly1305::encrypt_oneshot(
    std::span<std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, NONCE_SIZE> nonce,
    std::span<std::byte, TAG_SIZE> tag,
    std::span<const std::byte> aad
) noexcept {
    chacha20_poly1305 cipher;
    return cipher.encrypt(data, key, nonce, tag, aad);
}

std::error_code chacha20_poly1305::decrypt_oneshot(
    std::span<std::byte> data,
    std::span<const std::byte, KEY_SIZE> key,
    std::span<const std::byte, NONCE_SIZE> nonce,
    std::span<const std::byte, TAG_SIZE> tag,
    std::span<const std::byte> aad
) noexcept {
    chacha20_poly1305 cipher;
    return cipher.decrypt(data, key, nonce, tag, aad);
}

} // namespace psyfer