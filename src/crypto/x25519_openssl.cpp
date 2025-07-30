/**
 * @file x25519_openssl.cpp
 * @brief X25519 key exchange implementation using OpenSSL
 */

#include <psyfer.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <memory>

namespace psyfer {

/**
 * @brief Generate X25519 private key using OpenSSL
 */
std::error_code x25519_openssl_generate_private_key(
    std::span<std::byte, x25519::PRIVATE_KEY_SIZE> private_key
) noexcept {
    // Create EVP_PKEY_CTX for X25519
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr),
        EVP_PKEY_CTX_free
    );
    
    if (!ctx) {
        return std::make_error_code(std::errc::operation_not_supported);
    }
    
    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        return std::make_error_code(std::errc::operation_not_permitted);
    }
    
    // Generate the key pair
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        return std::make_error_code(std::errc::operation_not_permitted);
    }
    
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(pkey_raw, EVP_PKEY_free);
    
    // Extract the raw private key
    size_t key_len = x25519::PRIVATE_KEY_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), 
                                      reinterpret_cast<unsigned char*>(private_key.data()), 
                                      &key_len) != 1) {
        return std::make_error_code(std::errc::operation_not_permitted);
    }
    
    if (key_len != x25519::PRIVATE_KEY_SIZE) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    return {};
}

/**
 * @brief Derive X25519 public key from private key using OpenSSL
 */
std::error_code x25519_openssl_derive_public_key(
    std::span<const std::byte, x25519::PRIVATE_KEY_SIZE> private_key,
    std::span<std::byte, x25519::PUBLIC_KEY_SIZE> public_key
) noexcept {
    // Create EVP_PKEY from raw private key
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                     reinterpret_cast<const unsigned char*>(private_key.data()),
                                     x25519::PRIVATE_KEY_SIZE),
        EVP_PKEY_free
    );
    
    if (!pkey) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    // Extract the raw public key
    size_t key_len = x25519::PUBLIC_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pkey.get(),
                                     reinterpret_cast<unsigned char*>(public_key.data()),
                                     &key_len) != 1) {
        return std::make_error_code(std::errc::operation_not_permitted);
    }
    
    if (key_len != x25519::PUBLIC_KEY_SIZE) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    return {};
}

/**
 * @brief Compute X25519 shared secret using OpenSSL
 */
std::error_code x25519_openssl_compute_shared_secret(
    std::span<const std::byte, x25519::PRIVATE_KEY_SIZE> private_key,
    std::span<const std::byte, x25519::PUBLIC_KEY_SIZE> peer_public_key,
    std::span<std::byte, x25519::SHARED_SECRET_SIZE> shared_secret
) noexcept {
    // Create EVP_PKEY from our private key
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> our_key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                     reinterpret_cast<const unsigned char*>(private_key.data()),
                                     x25519::PRIVATE_KEY_SIZE),
        EVP_PKEY_free
    );
    
    if (!our_key) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    // Create EVP_PKEY from peer's public key
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> peer_key(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                    reinterpret_cast<const unsigned char*>(peer_public_key.data()),
                                    x25519::PUBLIC_KEY_SIZE),
        EVP_PKEY_free
    );
    
    if (!peer_key) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    // Create derivation context
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new(our_key.get(), nullptr),
        EVP_PKEY_CTX_free
    );
    
    if (!ctx) {
        return std::make_error_code(std::errc::operation_not_supported);
    }
    
    // Initialize key derivation
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
        return std::make_error_code(std::errc::operation_not_permitted);
    }
    
    // Set the peer key
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get()) <= 0) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    // Derive the shared secret
    size_t secret_len = x25519::SHARED_SECRET_SIZE;
    if (EVP_PKEY_derive(ctx.get(),
                        reinterpret_cast<unsigned char*>(shared_secret.data()),
                        &secret_len) <= 0) {
        return std::make_error_code(std::errc::operation_not_permitted);
    }
    
    if (secret_len != x25519::SHARED_SECRET_SIZE) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    return {};
}

} // namespace psyfer