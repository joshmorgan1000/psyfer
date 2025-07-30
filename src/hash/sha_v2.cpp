/**
 * @file sha_v2.cpp
 * @brief SHA-256 and SHA-512 implementation with runtime hardware/software switching
 */

#include <psyfer.hpp>
#include <cstring>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#endif

namespace psyfer {

// SHA-256 constants
static constexpr uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-512 constants
static constexpr uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// Rotate right
template<typename T>
constexpr T rotr(T x, unsigned n) {
    return (x >> n) | (x << (sizeof(T) * 8 - n));
}

// SHA-256 functions
static uint32_t Ch256(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t Maj256(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t Sigma0_256(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t Sigma1_256(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t sigma0_256(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t sigma1_256(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// SHA-512 functions
static uint64_t Ch512(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
static uint64_t Maj512(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint64_t Sigma0_512(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
static uint64_t Sigma1_512(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
static uint64_t sigma0_512(uint64_t x) { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
static uint64_t sigma1_512(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }

// ────────────────────────────────────────────────────────────────────────────
// SHA-256 implementation
// ────────────────────────────────────────────────────────────────────────────

class sha256_hasher::impl {
public:
    // Software implementation state
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
    bool finalized = false;
    
#ifdef __APPLE__
    // Hardware implementation state
    CC_SHA256_CTX hw_ctx;
    bool use_hardware = false;
#endif
    
    impl() noexcept {
#ifdef __APPLE__
        // Use hardware unless explicitly disabled
        use_hardware = !config::is_software_only();
        if (use_hardware) {
            CC_SHA256_Init(&hw_ctx);
        } else {
            reset_software();
        }
#else
        reset_software();
#endif
    }
    
    void reset_software() noexcept {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        count = 0;
        finalized = false;
        std::memset(buffer, 0, sizeof(buffer));
    }
    
    void transform(const uint8_t* data) noexcept {
        uint32_t W[64];
        uint32_t a, b, c, d, e, f, g, h;
        
        // Copy data to W[0..15]
        for (int i = 0; i < 16; i++) {
            W[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
                   (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(data[i * 4 + 3]));
        }
        
        // Extend W[16..63]
        for (int i = 16; i < 64; i++) {
            W[i] = sigma1_256(W[i - 2]) + W[i - 7] + sigma0_256(W[i - 15]) + W[i - 16];
        }
        
        // Initialize working variables
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];
        
        // Main loop
        for (int i = 0; i < 64; i++) {
            uint32_t T1 = h + Sigma1_256(e) + Ch256(e, f, g) + K256[i] + W[i];
            uint32_t T2 = Sigma0_256(a) + Maj256(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        
        // Update state
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
    
    void update(const uint8_t* data, size_t len) noexcept {
        if (finalized) return;
        
#ifdef __APPLE__
        if (use_hardware) {
            CC_SHA256_Update(&hw_ctx, data, static_cast<CC_LONG>(len));
            return;
        }
#endif
        
        // Software implementation
        size_t buffer_idx = count & 0x3F;
        count += len;
        
        // Process any pending bytes
        if (buffer_idx && buffer_idx + len >= 64) {
            size_t copy_len = 64 - buffer_idx;
            std::memcpy(buffer + buffer_idx, data, copy_len);
            transform(buffer);
            data += copy_len;
            len -= copy_len;
            buffer_idx = 0;
        }
        
        // Process full blocks
        while (len >= 64) {
            transform(data);
            data += 64;
            len -= 64;
        }
        
        // Save remaining bytes
        if (len > 0) {
            std::memcpy(buffer + buffer_idx, data, len);
        }
    }
    
    void finalize(uint8_t* output) noexcept {
        if (finalized) return;
        
#ifdef __APPLE__
        if (use_hardware) {
            CC_SHA256_Final(output, &hw_ctx);
            finalized = true;
            return;
        }
#endif
        
        // Software implementation
        size_t buffer_idx = count & 0x3F;
        
        // Padding
        buffer[buffer_idx++] = 0x80;
        
        if (buffer_idx > 56) {
            std::memset(buffer + buffer_idx, 0, 64 - buffer_idx);
            transform(buffer);
            buffer_idx = 0;
        }
        
        std::memset(buffer + buffer_idx, 0, 56 - buffer_idx);
        
        // Append length in bits
        uint64_t bit_length = count * 8;
        for (int i = 0; i < 8; i++) {
            buffer[56 + i] = static_cast<uint8_t>(bit_length >> (56 - i * 8));
        }
        
        transform(buffer);
        
        // Copy state to output
        for (int i = 0; i < 8; i++) {
            output[i * 4] = static_cast<uint8_t>(state[i] >> 24);
            output[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            output[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            output[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
        
        finalized = true;
    }
    
    void reset() noexcept {
#ifdef __APPLE__
        use_hardware = !config::is_software_only();
        if (use_hardware) {
            CC_SHA256_Init(&hw_ctx);
            finalized = false;
        } else {
            reset_software();
        }
#else
        reset_software();
#endif
    }
};

// ────────────────────────────────────────────────────────────────────────────
// SHA-512 implementation
// ────────────────────────────────────────────────────────────────────────────

class sha512_hasher::impl {
public:
    // Software implementation state
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
    bool finalized = false;
    
#ifdef __APPLE__
    // Hardware implementation state
    CC_SHA512_CTX hw_ctx;
    bool use_hardware = false;
#endif
    
    impl() noexcept {
#ifdef __APPLE__
        // Use hardware unless explicitly disabled
        use_hardware = !config::is_software_only();
        if (use_hardware) {
            CC_SHA512_Init(&hw_ctx);
        } else {
            reset_software();
        }
#else
        reset_software();
#endif
    }
    
    void reset_software() noexcept {
        state[0] = 0x6a09e667f3bcc908ULL;
        state[1] = 0xbb67ae8584caa73bULL;
        state[2] = 0x3c6ef372fe94f82bULL;
        state[3] = 0xa54ff53a5f1d36f1ULL;
        state[4] = 0x510e527fade682d1ULL;
        state[5] = 0x9b05688c2b3e6c1fULL;
        state[6] = 0x1f83d9abfb41bd6bULL;
        state[7] = 0x5be0cd19137e2179ULL;
        count[0] = count[1] = 0;
        finalized = false;
        std::memset(buffer, 0, sizeof(buffer));
    }
    
    void transform(const uint8_t* data) noexcept {
        uint64_t W[80];
        uint64_t a, b, c, d, e, f, g, h;
        
        // Copy data to W[0..15]
        for (int i = 0; i < 16; i++) {
            W[i] = (static_cast<uint64_t>(data[i * 8]) << 56) |
                   (static_cast<uint64_t>(data[i * 8 + 1]) << 48) |
                   (static_cast<uint64_t>(data[i * 8 + 2]) << 40) |
                   (static_cast<uint64_t>(data[i * 8 + 3]) << 32) |
                   (static_cast<uint64_t>(data[i * 8 + 4]) << 24) |
                   (static_cast<uint64_t>(data[i * 8 + 5]) << 16) |
                   (static_cast<uint64_t>(data[i * 8 + 6]) << 8) |
                   (static_cast<uint64_t>(data[i * 8 + 7]));
        }
        
        // Extend W[16..79]
        for (int i = 16; i < 80; i++) {
            W[i] = sigma1_512(W[i - 2]) + W[i - 7] + sigma0_512(W[i - 15]) + W[i - 16];
        }
        
        // Initialize working variables
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];
        
        // Main loop
        for (int i = 0; i < 80; i++) {
            uint64_t T1 = h + Sigma1_512(e) + Ch512(e, f, g) + K512[i] + W[i];
            uint64_t T2 = Sigma0_512(a) + Maj512(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        
        // Update state
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
    
    void update(const uint8_t* data, size_t len) noexcept {
        if (finalized) return;
        
#ifdef __APPLE__
        if (use_hardware) {
            CC_SHA512_Update(&hw_ctx, data, static_cast<CC_LONG>(len));
            return;
        }
#endif
        
        // Software implementation
        size_t buffer_idx = count[0] & 0x7F;
        
        // Update count
        count[0] += len;
        if (count[0] < len) {
            count[1]++;
        }
        
        // Process any pending bytes
        if (buffer_idx && buffer_idx + len >= 128) {
            size_t copy_len = 128 - buffer_idx;
            std::memcpy(buffer + buffer_idx, data, copy_len);
            transform(buffer);
            data += copy_len;
            len -= copy_len;
            buffer_idx = 0;
        }
        
        // Process full blocks
        while (len >= 128) {
            transform(data);
            data += 128;
            len -= 128;
        }
        
        // Save remaining bytes
        if (len > 0) {
            std::memcpy(buffer + buffer_idx, data, len);
        }
    }
    
    void finalize(uint8_t* output) noexcept {
        if (finalized) return;
        
#ifdef __APPLE__
        if (use_hardware) {
            CC_SHA512_Final(output, &hw_ctx);
            finalized = true;
            return;
        }
#endif
        
        // Software implementation
        size_t buffer_idx = count[0] & 0x7F;
        
        // Padding
        buffer[buffer_idx++] = 0x80;
        
        if (buffer_idx > 112) {
            std::memset(buffer + buffer_idx, 0, 128 - buffer_idx);
            transform(buffer);
            buffer_idx = 0;
        }
        
        std::memset(buffer + buffer_idx, 0, 112 - buffer_idx);
        
        // Append length in bits
        uint64_t bit_length_high = (count[1] << 3) | (count[0] >> 61);
        uint64_t bit_length_low = count[0] << 3;
        
        for (int i = 0; i < 8; i++) {
            buffer[112 + i] = static_cast<uint8_t>(bit_length_high >> (56 - i * 8));
            buffer[120 + i] = static_cast<uint8_t>(bit_length_low >> (56 - i * 8));
        }
        
        transform(buffer);
        
        // Copy state to output
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                output[i * 8 + j] = static_cast<uint8_t>(state[i] >> (56 - j * 8));
            }
        }
        
        finalized = true;
    }
    
    void reset() noexcept {
#ifdef __APPLE__
        use_hardware = !config::is_software_only();
        if (use_hardware) {
            CC_SHA512_Init(&hw_ctx);
            finalized = false;
        } else {
            reset_software();
        }
#else
        reset_software();
#endif
    }
};

// ────────────────────────────────────────────────────────────────────────────
// Public interface implementation
// ────────────────────────────────────────────────────────────────────────────

sha256_hasher::sha256_hasher() noexcept : pimpl(std::make_unique<impl>()) {}
sha256_hasher::~sha256_hasher() = default;

void sha256_hasher::update(std::span<const std::byte> data) noexcept {
    pimpl->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void sha256_hasher::finalize(std::span<std::byte> output) noexcept {
    if (output.size() >= 32) {
        pimpl->finalize(reinterpret_cast<uint8_t*>(output.data()));
    }
}

void sha256_hasher::reset() noexcept {
    pimpl->reset();
}

void sha256_hasher::hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept {
    if (output.size() < 32) return;
    
#ifdef __APPLE__
    if (!config::is_software_only()) {
        CC_SHA256(input.data(), static_cast<CC_LONG>(input.size()), 
                  reinterpret_cast<uint8_t*>(output.data()));
        return;
    }
#endif
    
    // Software implementation
    sha256_hasher hasher;
    hasher.update(input);
    hasher.finalize(output);
}

sha512_hasher::sha512_hasher() noexcept : pimpl(std::make_unique<impl>()) {}
sha512_hasher::~sha512_hasher() = default;

void sha512_hasher::update(std::span<const std::byte> data) noexcept {
    pimpl->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void sha512_hasher::finalize(std::span<std::byte> output) noexcept {
    if (output.size() >= 64) {
        pimpl->finalize(reinterpret_cast<uint8_t*>(output.data()));
    }
}

void sha512_hasher::reset() noexcept {
    pimpl->reset();
}

void sha512_hasher::hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept {
    if (output.size() < 64) return;
    
#ifdef __APPLE__
    if (!config::is_software_only()) {
        CC_SHA512(input.data(), static_cast<CC_LONG>(input.size()), 
                  reinterpret_cast<uint8_t*>(output.data()));
        return;
    }
#endif
    
    // Software implementation
    sha512_hasher hasher;
    hasher.update(input);
    hasher.finalize(output);
}

} // namespace psyfer