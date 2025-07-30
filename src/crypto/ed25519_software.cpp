/**
 * @file ed25519.cpp
 * @brief Ed25519 implementation
 */

#include <psyfer.hpp>
#include <array>
#include <cstring>

#ifdef __APPLE__
// Use CryptoKit on macOS/iOS
extern "C" {
#include "ed25519_cryptokit.h"
}
#endif

// Forward declarations for Ed25519 operations
namespace psyfer {
    // Field element
    typedef struct {
        int32_t v[10];
    } fe;
    
    // Group elements
    typedef struct {
        fe X;
        fe Y;
        fe Z;
    } ge_p2;
    
    typedef struct {
        fe X;
        fe Y;
        fe Z;
        fe T;
    } ge_p3;
    
    // Operations (implemented in ed25519_ops.cpp)
    extern void sc_reduce(uint8_t* s, uint8_t* out);
    extern bool sc_is_canonical(const uint8_t* s);
    extern void sc_muladd(uint8_t* out, const uint8_t* a, const uint8_t* b, const uint8_t* c);
    extern void ge_scalarmult_base(ge_p3* h, const uint8_t* a);
    extern void ge_p3_tobytes(uint8_t* s, const ge_p3* h);
    extern int ge_frombytes_negate_vartime(ge_p3* h, const uint8_t* s);
    extern void ge_double_scalarmult_vartime(ge_p2* r, const uint8_t* a, const ge_p3* A, const uint8_t* b);
    extern void ge_tobytes(uint8_t* s, const ge_p2* h);
}

namespace psyfer {

result<ed25519::key_pair> ed25519::generate_key_pair() noexcept {
    // Always use software implementation for deterministic signatures
    // CryptoKit uses randomized signatures which don't match RFC 8032
    
    // Generate random seed
    std::array<std::byte, SEED_SIZE> seed;
    auto ec = secure_random::generate(seed);
    if (ec) {
        return std::unexpected(ec);
    }
    
    return key_pair_from_seed(seed);
}

result<ed25519::key_pair> ed25519::key_pair_from_seed(
    std::span<const std::byte, SEED_SIZE> seed
) noexcept {
    key_pair kp;
    
    // Always use software implementation for deterministic signatures
    // Copy the seed as the private key (Ed25519 stores the seed)
    std::memcpy(kp.private_key.data(), seed.data(), SEED_SIZE);
    
    // Derive public key
    public_key_from_private(kp.private_key, kp.public_key);
    
    return kp;
}

void ed25519::public_key_from_private(
    std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
    std::span<std::byte, PUBLIC_KEY_SIZE> public_key
) noexcept {
    // Always use software implementation for consistency
    // Derive public key from private key following Ed25519 spec
    
    // Hash the private key to get the expanded key
    std::array<std::byte, 64> expanded_key;
    sha512 hasher;
    hasher.update(private_key);
    hasher.finalize(expanded_key);
    
    // Apply Ed25519 clamping to the scalar
    auto* scalar = reinterpret_cast<uint8_t*>(expanded_key.data());
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    
    // Compute public key = scalar * base point
    ge_p3 public_point;
    ge_scalarmult_base(&public_point, scalar);
    
    // Encode the public key point
    ge_p3_tobytes(reinterpret_cast<uint8_t*>(public_key.data()), &public_point);
    
    // Clear sensitive data
    secure_clear(expanded_key.data(), expanded_key.size());
}

std::error_code ed25519::sign(
    std::span<const std::byte> message,
    std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
    std::span<std::byte, SIGNATURE_SIZE> signature
) noexcept {
    return sign_detached(message, private_key, signature);
}

std::error_code ed25519::sign_detached(
    std::span<const std::byte> message,
    std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
    std::span<std::byte, SIGNATURE_SIZE> signature
) noexcept {
    // Always use software implementation for deterministic signatures
    // CryptoKit uses randomized signatures which don't match RFC 8032
    
    // Software implementation of Ed25519 signing
    // This is a complete implementation following RFC 8032
    
    // Step 1: Hash the private key to get the expanded key
    std::array<std::byte, 64> expanded_key;
    sha512 key_hasher;
    key_hasher.update(private_key);
    key_hasher.finalize(expanded_key);
    
    // Apply Ed25519 clamping to the scalar
    auto* scalar = reinterpret_cast<uint8_t*>(expanded_key.data());
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    
    // Step 2: Compute the public key A = a * G
    std::array<std::byte, PUBLIC_KEY_SIZE> computed_public_key;
    public_key_from_private(private_key, computed_public_key);
    
    // Step 3: Compute r = SHA512(prefix || message)
    std::array<std::byte, 64> r_hash;
    sha512 r_hasher;
    r_hasher.update(std::span<const std::byte>{expanded_key.data() + 32, 32}); // prefix
    r_hasher.update(message);
    r_hasher.finalize(r_hash);
    
    // Reduce r modulo the group order
    uint8_t r_reduced[32];
    sc_reduce(reinterpret_cast<uint8_t*>(r_hash.data()), r_reduced);
    
    // Step 4: Compute R = r * G
    ge_p3 R_point;
    ge_scalarmult_base(&R_point, r_reduced);
    
    // Encode R
    uint8_t R_bytes[32];
    ge_p3_tobytes(R_bytes, &R_point);
    
    // Step 5: Compute k = SHA512(R || A || M)
    std::array<std::byte, 64> k_hash;
    sha512 k_hasher;
    k_hasher.update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(R_bytes), 32});
    k_hasher.update(computed_public_key);
    k_hasher.update(message);
    k_hasher.finalize(k_hash);
    
    // Reduce k modulo the group order
    uint8_t k_reduced[32];
    sc_reduce(reinterpret_cast<uint8_t*>(k_hash.data()), k_reduced);
    
    // Step 6: Compute S = (r + k * a) mod l
    uint8_t S_bytes[32];
    sc_muladd(S_bytes, k_reduced, scalar, r_reduced);
    
    // Step 7: Return signature = R || S
    std::memcpy(signature.data(), R_bytes, 32);
    std::memcpy(signature.data() + 32, S_bytes, 32);
    
    // Clear sensitive data
    secure_clear(expanded_key.data(), expanded_key.size());
    secure_clear(r_hash.data(), r_hash.size());
    secure_clear(k_hash.data(), k_hash.size());
    secure_clear(r_reduced, sizeof(r_reduced));
    secure_clear(k_reduced, sizeof(k_reduced));
    
    return {};
}

bool ed25519::verify(
    std::span<const std::byte> message,
    std::span<const std::byte, SIGNATURE_SIZE> signature,
    std::span<const std::byte, PUBLIC_KEY_SIZE> public_key
) noexcept {
    return verify_detached(message, signature, public_key);
}

bool ed25519::verify_detached(
    std::span<const std::byte> message,
    std::span<const std::byte, SIGNATURE_SIZE> signature,
    std::span<const std::byte, PUBLIC_KEY_SIZE> public_key
) noexcept {
    // Always use software implementation for consistency with signing
    
    // Software implementation of Ed25519 verification
    // Following RFC 8032
    
    // Step 1: Parse signature = (R, S)
    const uint8_t* R_bytes = reinterpret_cast<const uint8_t*>(signature.data());
    const uint8_t* S_bytes = reinterpret_cast<const uint8_t*>(signature.data() + 32);
    
    // Step 2: Check if S < l (group order)
    if (!sc_is_canonical(S_bytes)) {
        return false;
    }
    
    // Step 3: Parse the public key point A
    ge_p3 A_point;
    if (ge_frombytes_negate_vartime(&A_point, reinterpret_cast<const uint8_t*>(public_key.data())) != 0) {
        return false;
    }
    
    // Step 4: Compute k = SHA512(R || A || M)
    std::array<std::byte, 64> k_hash;
    sha512 k_hasher;
    k_hasher.update(std::span<const std::byte>{signature.data(), 32}); // R
    k_hasher.update(public_key);
    k_hasher.update(message);
    k_hasher.finalize(k_hash);
    
    // Reduce k modulo the group order
    uint8_t k_reduced[32];
    sc_reduce(reinterpret_cast<uint8_t*>(k_hash.data()), k_reduced);
    
    // Step 5: Compute [S]B - [k]A
    ge_p2 check_point;
    ge_double_scalarmult_vartime(&check_point, k_reduced, &A_point, S_bytes);
    
    // Step 6: Encode the check point
    uint8_t check_bytes[32];
    ge_tobytes(check_bytes, &check_point);
    
    // Step 7: Verify R == [S]B - [k]A
    bool valid = secure_compare(R_bytes, check_bytes, 32);
    
    // Clear sensitive data
    secure_clear(k_hash.data(), k_hash.size());
    secure_clear(k_reduced, sizeof(k_reduced));
    
    return valid;
}

bool ed25519::hardware_accelerated() noexcept {
    // Always return false since we're using software implementation
    // for deterministic signatures (CryptoKit uses randomized signatures)
    return false;
}

} // namespace psyfer