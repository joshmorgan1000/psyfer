/**
 * @file ed25519_openssl.cpp
 * @brief Ed25519 implementation using OpenSSL backend
 */

#include <psyfer.hpp>
#include <cstring>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace psyfer::crypto {

result<ed25519::key_pair> ed25519::generate_key_pair() noexcept {
    // Generate random seed
    std::array<std::byte, SEED_SIZE> seed;
    auto ec = utils::secure_random::generate(seed);
    if (ec) {
        return std::unexpected(ec);
    }
    
    return key_pair_from_seed(seed);
}

result<ed25519::key_pair> ed25519::key_pair_from_seed(
    std::span<const std::byte, SEED_SIZE> seed
) noexcept {
    key_pair kp;
    
    // Copy seed as private key
    std::memcpy(kp.private_key.data(), seed.data(), SEED_SIZE);
    
    // Use OpenSSL to derive public key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(seed.data()),
        SEED_SIZE
    );
    
    if (!pkey) {
        return std::unexpected(make_error_code(error_code::crypto_error));
    }
    
    size_t pubkey_len = PUBLIC_KEY_SIZE;
    int result = EVP_PKEY_get_raw_public_key(
        pkey,
        reinterpret_cast<unsigned char*>(kp.public_key.data()),
        &pubkey_len
    );
    
    EVP_PKEY_free(pkey);
    
    if (result != 1 || pubkey_len != PUBLIC_KEY_SIZE) {
        return std::unexpected(make_error_code(error_code::crypto_error));
    }
    
    return kp;
}

void ed25519::public_key_from_private(
    std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
    std::span<std::byte, PUBLIC_KEY_SIZE> public_key
) noexcept {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(private_key.data()),
        PRIVATE_KEY_SIZE
    );
    
    if (!pkey) {
        // Zero out on error
        utils::secure_clear(public_key.data(), public_key.size());
        return;
    }
    
    size_t pubkey_len = PUBLIC_KEY_SIZE;
    int result = EVP_PKEY_get_raw_public_key(
        pkey,
        reinterpret_cast<unsigned char*>(public_key.data()),
        &pubkey_len
    );
    
    EVP_PKEY_free(pkey);
    
    if (result != 1 || pubkey_len != PUBLIC_KEY_SIZE) {
        // Zero out on error
        utils::secure_clear(public_key.data(), public_key.size());
    }
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
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(private_key.data()),
        PRIVATE_KEY_SIZE
    );
    
    if (!pkey) {
        return make_error_code(error_code::crypto_error);
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return make_error_code(error_code::crypto_error);
    }
    
    std::error_code ec;
    
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) != 1) {
        ec = make_error_code(error_code::crypto_error);
    } else {
        size_t sig_len = SIGNATURE_SIZE;
        if (EVP_DigestSign(
                mdctx,
                reinterpret_cast<unsigned char*>(signature.data()),
                &sig_len,
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()
            ) != 1 || sig_len != SIGNATURE_SIZE) {
            ec = make_error_code(error_code::crypto_error);
        }
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    return ec;
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
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        reinterpret_cast<const unsigned char*>(public_key.data()),
        PUBLIC_KEY_SIZE
    );
    
    if (!pkey) {
        return false;
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    
    bool valid = false;
    
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) == 1) {
        int result = EVP_DigestVerify(
            mdctx,
            reinterpret_cast<const unsigned char*>(signature.data()),
            SIGNATURE_SIZE,
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size()
        );
        valid = (result == 1);
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    return valid;
}

bool ed25519::hardware_accelerated() noexcept {
    // OpenSSL may use hardware acceleration internally
    return true;
}

} // namespace psyfer::crypto

#endif // HAVE_OPENSSL