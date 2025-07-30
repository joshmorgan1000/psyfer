/**
 * @file x25519.cpp
 * @brief X25519 key exchange implementation
 */

#include <psyfer.hpp>
#include <cstring>
#include <functional>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/x509.h>
#endif

namespace psyfer {

#ifdef HAVE_OPENSSL
static constexpr bool use_openssl = true;
#else
static constexpr bool use_openssl = false;
#endif

// Field arithmetic constants
static constexpr uint64_t MASK_51 = (1ULL << 51) - 1;

std::error_code x25519::generate_private_key(
    std::span<std::byte, PRIVATE_KEY_SIZE> private_key
) noexcept {
#ifdef HAVE_OPENSSL
    if (use_openssl) {
        // Use OpenSSL implementation from x25519_openssl.cpp
        extern std::error_code x25519_openssl_generate_private_key(
            std::span<std::byte, PRIVATE_KEY_SIZE> private_key);
        return x25519_openssl_generate_private_key(private_key);
    }
#endif
    
    // Generate random bytes
    if (auto ec = secure_random::generate(private_key); ec) {
        return ec;
    }
    
    // Apply X25519 clamping as per RFC 7748
    auto* key_bytes = reinterpret_cast<uint8_t*>(private_key.data());
    key_bytes[0] &= 248;
    key_bytes[31] &= 127;
    key_bytes[31] |= 64;
    
    return {};
}

std::error_code x25519::derive_public_key(
    std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
    std::span<std::byte, PUBLIC_KEY_SIZE> public_key
) noexcept {
#ifdef HAVE_OPENSSL
    if (use_openssl) {
        // Use OpenSSL implementation from x25519_openssl.cpp
        extern std::error_code x25519_openssl_derive_public_key(
            std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
            std::span<std::byte, PUBLIC_KEY_SIZE> public_key);
        return x25519_openssl_derive_public_key(private_key, public_key);
    }
#endif
    
    scalarmult(
        reinterpret_cast<uint8_t*>(public_key.data()),
        reinterpret_cast<const uint8_t*>(private_key.data()),
        BASEPOINT.data()
    );
    
    return {};
}

std::error_code x25519::compute_shared_secret(
    std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
    std::span<const std::byte, PUBLIC_KEY_SIZE> peer_public_key,
    std::span<std::byte, SHARED_SECRET_SIZE> shared_secret
) noexcept {
#ifdef HAVE_OPENSSL
    if (use_openssl) {
        // Use OpenSSL implementation from x25519_openssl.cpp
        extern std::error_code x25519_openssl_compute_shared_secret(
            std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
            std::span<const std::byte, PUBLIC_KEY_SIZE> peer_public_key,
            std::span<std::byte, SHARED_SECRET_SIZE> shared_secret);
        return x25519_openssl_compute_shared_secret(private_key, peer_public_key, shared_secret);
    }
#endif
    
    scalarmult(
        reinterpret_cast<uint8_t*>(shared_secret.data()),
        reinterpret_cast<const uint8_t*>(private_key.data()),
        reinterpret_cast<const uint8_t*>(peer_public_key.data())
    );
    
    // Check for all-zero output (failure case)
    bool all_zero = true;
    for (size_t i = 0; i < SHARED_SECRET_SIZE; ++i) {
        if (shared_secret[i] != std::byte{0}) {
            all_zero = false;
            break;
        }
    }
    
    if (all_zero) {
        return make_error_code(error_code::encryption_failed);
    }
    
    return {};
}

std::expected<x25519::key_pair, std::error_code> x25519::key_pair::generate() noexcept {
    key_pair kp;
    
    // Generate private key
    if (auto ec = x25519::generate_private_key(kp.private_key); ec) {
        return std::unexpected(ec);
    }
    
    // Derive public key
    if (auto ec = x25519::derive_public_key(kp.private_key, kp.public_key); ec) {
        return std::unexpected(ec);
    }
    
    // Clear private key on destruction
    auto cleanup = [&kp]() {
        secure_clear(kp.private_key.data(), PRIVATE_KEY_SIZE);
    };
    struct cleanup_guard {
        std::function<void()> fn;
        ~cleanup_guard() { fn(); }
    } guard{cleanup};
    
    return kp;
}

std::error_code x25519::key_pair::compute_shared_secret(
    std::span<const std::byte, PUBLIC_KEY_SIZE> peer_public_key,
    std::span<std::byte, SHARED_SECRET_SIZE> shared_secret
) const noexcept {
    return x25519::compute_shared_secret(private_key, peer_public_key, shared_secret);
}

// Field element operations
void x25519::fe_frombytes(fe& h, const uint8_t* s) noexcept {
    // Load bytes into 51-bit limbs
    uint64_t t0 = static_cast<uint64_t>(s[0]) |
                  (static_cast<uint64_t>(s[1]) << 8) |
                  (static_cast<uint64_t>(s[2]) << 16) |
                  (static_cast<uint64_t>(s[3]) << 24) |
                  (static_cast<uint64_t>(s[4]) << 32) |
                  (static_cast<uint64_t>(s[5]) << 40) |
                  ((static_cast<uint64_t>(s[6]) & 7) << 48);
    
    uint64_t t1 = (static_cast<uint64_t>(s[6]) >> 3) |
                  (static_cast<uint64_t>(s[7]) << 5) |
                  (static_cast<uint64_t>(s[8]) << 13) |
                  (static_cast<uint64_t>(s[9]) << 21) |
                  (static_cast<uint64_t>(s[10]) << 29) |
                  (static_cast<uint64_t>(s[11]) << 37) |
                  ((static_cast<uint64_t>(s[12]) & 63) << 45);
    
    uint64_t t2 = (static_cast<uint64_t>(s[12]) >> 6) |
                  (static_cast<uint64_t>(s[13]) << 2) |
                  (static_cast<uint64_t>(s[14]) << 10) |
                  (static_cast<uint64_t>(s[15]) << 18) |
                  (static_cast<uint64_t>(s[16]) << 26) |
                  (static_cast<uint64_t>(s[17]) << 34) |
                  (static_cast<uint64_t>(s[18]) << 42) |
                  ((static_cast<uint64_t>(s[19]) & 1) << 50);
    
    uint64_t t3 = (static_cast<uint64_t>(s[19]) >> 1) |
                  (static_cast<uint64_t>(s[20]) << 7) |
                  (static_cast<uint64_t>(s[21]) << 15) |
                  (static_cast<uint64_t>(s[22]) << 23) |
                  (static_cast<uint64_t>(s[23]) << 31) |
                  (static_cast<uint64_t>(s[24]) << 39) |
                  ((static_cast<uint64_t>(s[25]) & 15) << 47);
    
    uint64_t t4 = (static_cast<uint64_t>(s[25]) >> 4) |
                  (static_cast<uint64_t>(s[26]) << 4) |
                  (static_cast<uint64_t>(s[27]) << 12) |
                  (static_cast<uint64_t>(s[28]) << 20) |
                  (static_cast<uint64_t>(s[29]) << 28) |
                  (static_cast<uint64_t>(s[30]) << 36) |
                  (static_cast<uint64_t>(s[31]) << 44);
    
    h[0] = t0 & MASK_51;
    h[1] = t1 & MASK_51;
    h[2] = t2 & MASK_51;
    h[3] = t3 & MASK_51;
    h[4] = t4 & MASK_51;
}

void x25519::fe_tobytes(uint8_t* s, const fe& h) noexcept {
    // Reduce to canonical form
    fe t = h;
    
    // First, reduce coefficients
    t[0] += 19 * (t[4] >> 51);
    t[4] &= MASK_51;
    t[1] += t[0] >> 51;
    t[0] &= MASK_51;
    t[2] += t[1] >> 51;
    t[1] &= MASK_51;
    t[3] += t[2] >> 51;
    t[2] &= MASK_51;
    t[4] += t[3] >> 51;
    t[3] &= MASK_51;
    t[0] += 19 * (t[4] >> 51);
    t[4] &= MASK_51;
    
    // Second reduction
    t[1] += t[0] >> 51;
    t[0] &= MASK_51;
    t[2] += t[1] >> 51;
    t[1] &= MASK_51;
    t[3] += t[2] >> 51;
    t[2] &= MASK_51;
    t[4] += t[3] >> 51;
    t[3] &= MASK_51;
    t[0] += 19 * (t[4] >> 51);
    t[4] &= MASK_51;
    
    // Final reduction
    uint64_t carry = (t[0] + 19) >> 51;
    t[0] = (t[0] + 19) & MASK_51;
    t[1] += carry;
    carry = t[1] >> 51;
    t[1] &= MASK_51;
    t[2] += carry;
    carry = t[2] >> 51;
    t[2] &= MASK_51;
    t[3] += carry;
    carry = t[3] >> 51;
    t[3] &= MASK_51;
    t[4] += carry;
    carry = t[4] >> 51;
    t[4] &= MASK_51;
    
    // If carry is set, we subtracted 2^255 - 19
    uint64_t mask = carry - 1;
    t[0] = (t[0] & ~mask) | (h[0] & mask);
    t[1] = (t[1] & ~mask) | (h[1] & mask);
    t[2] = (t[2] & ~mask) | (h[2] & mask);
    t[3] = (t[3] & ~mask) | (h[3] & mask);
    t[4] = (t[4] & ~mask) | (h[4] & mask);
    
    // Store to bytes
    s[0] = static_cast<uint8_t>(t[0]);
    s[1] = static_cast<uint8_t>(t[0] >> 8);
    s[2] = static_cast<uint8_t>(t[0] >> 16);
    s[3] = static_cast<uint8_t>(t[0] >> 24);
    s[4] = static_cast<uint8_t>(t[0] >> 32);
    s[5] = static_cast<uint8_t>(t[0] >> 40);
    s[6] = static_cast<uint8_t>((t[0] >> 48) | (t[1] << 3));
    s[7] = static_cast<uint8_t>(t[1] >> 5);
    s[8] = static_cast<uint8_t>(t[1] >> 13);
    s[9] = static_cast<uint8_t>(t[1] >> 21);
    s[10] = static_cast<uint8_t>(t[1] >> 29);
    s[11] = static_cast<uint8_t>(t[1] >> 37);
    s[12] = static_cast<uint8_t>((t[1] >> 45) | (t[2] << 6));
    s[13] = static_cast<uint8_t>(t[2] >> 2);
    s[14] = static_cast<uint8_t>(t[2] >> 10);
    s[15] = static_cast<uint8_t>(t[2] >> 18);
    s[16] = static_cast<uint8_t>(t[2] >> 26);
    s[17] = static_cast<uint8_t>(t[2] >> 34);
    s[18] = static_cast<uint8_t>(t[2] >> 42);
    s[19] = static_cast<uint8_t>((t[2] >> 50) | (t[3] << 1));
    s[20] = static_cast<uint8_t>(t[3] >> 7);
    s[21] = static_cast<uint8_t>(t[3] >> 15);
    s[22] = static_cast<uint8_t>(t[3] >> 23);
    s[23] = static_cast<uint8_t>(t[3] >> 31);
    s[24] = static_cast<uint8_t>(t[3] >> 39);
    s[25] = static_cast<uint8_t>((t[3] >> 47) | (t[4] << 4));
    s[26] = static_cast<uint8_t>(t[4] >> 4);
    s[27] = static_cast<uint8_t>(t[4] >> 12);
    s[28] = static_cast<uint8_t>(t[4] >> 20);
    s[29] = static_cast<uint8_t>(t[4] >> 28);
    s[30] = static_cast<uint8_t>(t[4] >> 36);
    s[31] = static_cast<uint8_t>(t[4] >> 44);
}

void x25519::fe_add(fe& h, const fe& f, const fe& g) noexcept {
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

void x25519::fe_sub(fe& h, const fe& f, const fe& g) noexcept {
    // Add 2*p to f before subtracting g to ensure positive result
    static constexpr uint64_t TWO_P_0 = 0x3FFFFFFFFFFF6ULL;
    static constexpr uint64_t TWO_P_1234 = 0x3FFFFFFFFFFFULL;
    
    h[0] = f[0] + TWO_P_0 - g[0];
    h[1] = f[1] + TWO_P_1234 - g[1];
    h[2] = f[2] + TWO_P_1234 - g[2];
    h[3] = f[3] + TWO_P_1234 - g[3];
    h[4] = f[4] + TWO_P_1234 - g[4];
}

void x25519::fe_mul(fe& h, const fe& f, const fe& g) noexcept {
    // Schoolbook multiplication with 128-bit intermediate values
    using uint128_t = unsigned __int128;
    uint128_t t0 = static_cast<uint128_t>(f[0]) * g[0];
    uint128_t t1 = static_cast<uint128_t>(f[0]) * g[1] +
                   static_cast<uint128_t>(f[1]) * g[0];
    uint128_t t2 = static_cast<uint128_t>(f[0]) * g[2] +
                   static_cast<uint128_t>(f[1]) * g[1] +
                   static_cast<uint128_t>(f[2]) * g[0];
    uint128_t t3 = static_cast<uint128_t>(f[0]) * g[3] +
                   static_cast<uint128_t>(f[1]) * g[2] +
                   static_cast<uint128_t>(f[2]) * g[1] +
                   static_cast<uint128_t>(f[3]) * g[0];
    uint128_t t4 = static_cast<uint128_t>(f[0]) * g[4] +
                   static_cast<uint128_t>(f[1]) * g[3] +
                   static_cast<uint128_t>(f[2]) * g[2] +
                   static_cast<uint128_t>(f[3]) * g[1] +
                   static_cast<uint128_t>(f[4]) * g[0];
    uint128_t t5 = static_cast<uint128_t>(f[1]) * g[4] +
                   static_cast<uint128_t>(f[2]) * g[3] +
                   static_cast<uint128_t>(f[3]) * g[2] +
                   static_cast<uint128_t>(f[4]) * g[1];
    uint128_t t6 = static_cast<uint128_t>(f[2]) * g[4] +
                   static_cast<uint128_t>(f[3]) * g[3] +
                   static_cast<uint128_t>(f[4]) * g[2];
    uint128_t t7 = static_cast<uint128_t>(f[3]) * g[4] +
                   static_cast<uint128_t>(f[4]) * g[3];
    uint128_t t8 = static_cast<uint128_t>(f[4]) * g[4];
    
    // Reduce modulo 2^255 - 19
    t0 += 19 * (t5 >> 51);
    t1 += 19 * (t6 >> 51) + (t5 & MASK_51);
    t2 += 19 * (t7 >> 51) + (t6 & MASK_51);
    t3 += 19 * (t8 >> 51) + (t7 & MASK_51);
    t4 += t8 & MASK_51;
    
    // Carry propagation
    t1 += t0 >> 51;
    h[0] = t0 & MASK_51;
    t2 += t1 >> 51;
    h[1] = t1 & MASK_51;
    t3 += t2 >> 51;
    h[2] = t2 & MASK_51;
    t4 += t3 >> 51;
    h[3] = t3 & MASK_51;
    h[0] += 19 * (t4 >> 51);
    h[4] = t4 & MASK_51;
    h[1] += h[0] >> 51;
    h[0] &= MASK_51;
}

void x25519::fe_sq(fe& h, const fe& f) noexcept {
    // Optimized squaring
    using uint128_t = unsigned __int128;
    uint128_t t0 = static_cast<uint128_t>(f[0]) * f[0];
    uint128_t t1 = 2 * static_cast<uint128_t>(f[0]) * f[1];
    uint128_t t2 = 2 * static_cast<uint128_t>(f[0]) * f[2] +
                   static_cast<uint128_t>(f[1]) * f[1];
    uint128_t t3 = 2 * static_cast<uint128_t>(f[0]) * f[3] +
                   2 * static_cast<uint128_t>(f[1]) * f[2];
    uint128_t t4 = 2 * static_cast<uint128_t>(f[0]) * f[4] +
                   2 * static_cast<uint128_t>(f[1]) * f[3] +
                   static_cast<uint128_t>(f[2]) * f[2];
    uint128_t t5 = 2 * static_cast<uint128_t>(f[1]) * f[4] +
                   2 * static_cast<uint128_t>(f[2]) * f[3];
    uint128_t t6 = 2 * static_cast<uint128_t>(f[2]) * f[4] +
                   static_cast<uint128_t>(f[3]) * f[3];
    uint128_t t7 = 2 * static_cast<uint128_t>(f[3]) * f[4];
    uint128_t t8 = static_cast<uint128_t>(f[4]) * f[4];
    
    // Reduce modulo 2^255 - 19
    t0 += 19 * (t5 >> 51);
    t1 += 19 * (t6 >> 51) + (t5 & MASK_51);
    t2 += 19 * (t7 >> 51) + (t6 & MASK_51);
    t3 += 19 * (t8 >> 51) + (t7 & MASK_51);
    t4 += t8 & MASK_51;
    
    // Carry propagation
    t1 += t0 >> 51;
    h[0] = t0 & MASK_51;
    t2 += t1 >> 51;
    h[1] = t1 & MASK_51;
    t3 += t2 >> 51;
    h[2] = t2 & MASK_51;
    t4 += t3 >> 51;
    h[3] = t3 & MASK_51;
    h[0] += 19 * (t4 >> 51);
    h[4] = t4 & MASK_51;
    h[1] += h[0] >> 51;
    h[0] &= MASK_51;
}

void x25519::fe_mul121666(fe& h, const fe& f) noexcept {
    // Multiply by the constant 121666
    using uint128_t = unsigned __int128;
    uint128_t t0 = 121666 * static_cast<uint128_t>(f[0]);
    uint128_t t1 = 121666 * static_cast<uint128_t>(f[1]);
    uint128_t t2 = 121666 * static_cast<uint128_t>(f[2]);
    uint128_t t3 = 121666 * static_cast<uint128_t>(f[3]);
    uint128_t t4 = 121666 * static_cast<uint128_t>(f[4]);
    
    // Carry propagation
    t1 += t0 >> 51;
    h[0] = t0 & MASK_51;
    t2 += t1 >> 51;
    h[1] = t1 & MASK_51;
    t3 += t2 >> 51;
    h[2] = t2 & MASK_51;
    t4 += t3 >> 51;
    h[3] = t3 & MASK_51;
    h[0] += 19 * (t4 >> 51);
    h[4] = t4 & MASK_51;
    h[1] += h[0] >> 51;
    h[0] &= MASK_51;
}

void x25519::fe_invert(fe& out, const fe& z) noexcept {
    // Compute z^(p-2) = z^(2^255 - 21) using square-and-multiply
    fe t0, t1, t2, t3;
    
    // t0 = z^2
    fe_sq(t0, z);
    
    // t1 = z^4
    fe_sq(t1, t0);
    
    // t1 = z^8
    fe_sq(t1, t1);
    
    // t1 = z^9
    fe_mul(t1, t1, z);
    
    // t0 = z^11
    fe_mul(t0, t0, t1);
    
    // t2 = z^22
    fe_sq(t2, t0);
    
    // t1 = z^31 = z^(2^5 - 1)
    fe_mul(t1, t1, t2);
    
    // t2 = z^(2^10 - 1)
    fe_sq(t2, t1);
    for (int i = 1; i < 5; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t2, t2, t1);
    
    // t3 = z^(2^20 - 1)
    fe_sq(t3, t2);
    for (int i = 1; i < 10; ++i) {
        fe_sq(t3, t3);
    }
    fe_mul(t3, t3, t2);
    
    // t3 = z^(2^40 - 1)
    fe_sq(t3, t3);
    for (int i = 1; i < 20; ++i) {
        fe_sq(t3, t3);
    }
    fe_mul(t2, t3, t2);
    
    // t2 = z^(2^50 - 1)
    fe_sq(t2, t2);
    for (int i = 1; i < 10; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    
    // t2 = z^(2^100 - 1)
    fe_sq(t2, t1);
    for (int i = 1; i < 50; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t2, t2, t1);
    
    // t2 = z^(2^200 - 1)
    fe_sq(t3, t2);
    for (int i = 1; i < 100; ++i) {
        fe_sq(t3, t3);
    }
    fe_mul(t2, t3, t2);
    
    // t2 = z^(2^250 - 1)
    fe_sq(t2, t2);
    for (int i = 1; i < 50; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    
    // t1 = z^(2^255 - 21)
    fe_sq(t1, t1);
    for (int i = 1; i < 5; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(out, t1, t0);
}

void x25519::fe_cswap(fe& f, fe& g, unsigned int b) noexcept {
    // Constant-time conditional swap
    uint64_t mask = static_cast<uint64_t>(-static_cast<int64_t>(b));
    
    for (int i = 0; i < 5; ++i) {
        uint64_t x = f[i] ^ g[i];
        x &= mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

void x25519::scalarmult(uint8_t* out, const uint8_t* scalar, const uint8_t* point) noexcept {
    // Montgomery ladder for X25519
    uint8_t e[32];
    std::memcpy(e, scalar, 32);
    
    // Apply clamping
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    
    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    
    // x1 = point
    fe_frombytes(x1, point);
    
    // x2 = 1, z2 = 0 (point at infinity)
    x2 = {1, 0, 0, 0, 0};
    z2 = {0, 0, 0, 0, 0};
    
    // x3 = x1, z3 = 1
    x3 = x1;
    z3 = {1, 0, 0, 0, 0};
    
    unsigned int swap = 0;
    
    // Main loop
    for (int pos = 254; pos >= 0; --pos) {
        unsigned int b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;
        
        // Differential addition-and-doubling
        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }
    
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    
    // Compute x2 * z2^(p-2)
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    
    // Convert to bytes
    fe_tobytes(out, x2);
}

} // namespace psyfer