/**
 * @file ed25519_cryptokit.h
 * @brief C interface for Swift CryptoKit Ed25519 wrapper
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate Ed25519 key pair using CryptoKit
 * @param private_key Output buffer for 32-byte private key
 * @param public_key Output buffer for 32-byte public key
 * @return 0 on success, -1 on error
 */
int32_t ed25519_cryptokit_generate_key_pair(
    uint8_t* private_key,
    uint8_t* public_key
);

/**
 * @brief Generate Ed25519 key pair from seed using CryptoKit
 * @param seed 32-byte seed
 * @param private_key Output buffer for 32-byte private key
 * @param public_key Output buffer for 32-byte public key
 * @return 0 on success, -1 on error
 */
int32_t ed25519_cryptokit_key_pair_from_seed(
    const uint8_t* seed,
    uint8_t* private_key,
    uint8_t* public_key
);

/**
 * @brief Derive public key from private key using CryptoKit
 * @param private_key 32-byte private key
 * @param public_key Output buffer for 32-byte public key
 * @return 0 on success, -1 on error
 */
int32_t ed25519_cryptokit_public_key_from_private(
    const uint8_t* private_key,
    uint8_t* public_key
);

/**
 * @brief Sign message using Ed25519
 * @param message Message to sign
 * @param message_len Length of message
 * @param private_key 32-byte private key
 * @param signature Output buffer for 64-byte signature
 * @return 0 on success, -1 on error
 */
int32_t ed25519_cryptokit_sign(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature
);

/**
 * @brief Verify Ed25519 signature
 * @param message Message that was signed
 * @param message_len Length of message
 * @param signature 64-byte signature
 * @param public_key 32-byte public key
 * @return true if valid, false otherwise
 */
bool ed25519_cryptokit_verify(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    const uint8_t* public_key
);

/**
 * @brief Check if CryptoKit Ed25519 is available
 * @return true if available
 */
bool ed25519_cryptokit_available(void);

#ifdef __cplusplus
}
#endif