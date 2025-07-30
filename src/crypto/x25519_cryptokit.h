#pragma once
/**
 * @file x25519_cryptokit.h
 * @brief C interface for CryptoKit X25519 wrapper
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Generate X25519 private key using CryptoKit
 * @param private_key Output buffer for private key (32 bytes)
 * @return 0 on success, -1 on error
 */
int32_t x25519_cryptokit_generate_private_key(uint8_t* private_key);

/**
 * @brief Derive public key from private key using CryptoKit
 * @param private_key Input private key (32 bytes)
 * @param public_key Output buffer for public key (32 bytes)
 * @return 0 on success, -1 on error
 */
int32_t x25519_cryptokit_derive_public_key(
    const uint8_t* private_key,
    uint8_t* public_key
);

/**
 * @brief Compute shared secret using CryptoKit
 * @param private_key Our private key (32 bytes)
 * @param peer_public_key Peer's public key (32 bytes)
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @return 0 on success, -1 on error
 */
int32_t x25519_cryptokit_compute_shared_secret(
    const uint8_t* private_key,
    const uint8_t* peer_public_key,
    uint8_t* shared_secret
);

/**
 * @brief Check if CryptoKit is available
 * @return true if available, false otherwise
 */
bool x25519_cryptokit_available(void);

#ifdef __cplusplus
}
#endif
