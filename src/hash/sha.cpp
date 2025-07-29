/**
 * @file sha.cpp
 * @brief SHA-256 and SHA-512 implementation with hardware acceleration
 */

#include <psyfer/hash/sha.hpp>
#include <psyfer/utils/secure.hpp>
#include <cstring>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#else
// For non-Apple platforms, we'll need a software implementation
// This is a placeholder - in production, you'd want a proper implementation
#error "SHA implementation not available for this platform yet"
#endif

namespace psyfer::hash {

// ────────────────────────────────────────────────────────────────────────────
// SHA-256 implementation
// ────────────────────────────────────────────────────────────────────────────

class sha256::impl {
public:
#ifdef __APPLE__
    CC_SHA256_CTX ctx;
    bool finalized = false;
    
    impl() noexcept {
        CC_SHA256_Init(&ctx);
    }
    
    void update(const uint8_t* data, size_t len) noexcept {
        if (!finalized) {
            CC_SHA256_Update(&ctx, data, static_cast<CC_LONG>(len));
        }
    }
    
    void finalize(uint8_t* output) noexcept {
        if (!finalized) {
            CC_SHA256_Final(output, &ctx);
            finalized = true;
        }
    }
    
    void reset() noexcept {
        CC_SHA256_Init(&ctx);
        finalized = false;
    }
#endif
};

sha256::sha256() noexcept : pimpl(std::make_unique<impl>()) {}

sha256::~sha256() = default;

void sha256::update(std::span<const std::byte> data) noexcept {
    pimpl->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void sha256::finalize(std::span<std::byte> output) noexcept {
    if (output.size() < 32) return;
    pimpl->finalize(reinterpret_cast<uint8_t*>(output.data()));
}

void sha256::reset() noexcept {
    pimpl->reset();
}

void sha256::hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept {
    if (output.size() < 32) return;
    
#ifdef __APPLE__
    CC_SHA256(
        reinterpret_cast<const uint8_t*>(input.data()),
        static_cast<CC_LONG>(input.size()),
        reinterpret_cast<uint8_t*>(output.data())
    );
#endif
}

// ────────────────────────────────────────────────────────────────────────────
// SHA-512 implementation
// ────────────────────────────────────────────────────────────────────────────

class sha512::impl {
public:
#ifdef __APPLE__
    CC_SHA512_CTX ctx;
    bool finalized = false;
    
    impl() noexcept {
        CC_SHA512_Init(&ctx);
    }
    
    void update(const uint8_t* data, size_t len) noexcept {
        if (!finalized) {
            CC_SHA512_Update(&ctx, data, static_cast<CC_LONG>(len));
        }
    }
    
    void finalize(uint8_t* output) noexcept {
        if (!finalized) {
            CC_SHA512_Final(output, &ctx);
            finalized = true;
        }
    }
    
    void reset() noexcept {
        CC_SHA512_Init(&ctx);
        finalized = false;
    }
#endif
};

sha512::sha512() noexcept : pimpl(std::make_unique<impl>()) {}

sha512::~sha512() = default;

void sha512::update(std::span<const std::byte> data) noexcept {
    pimpl->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void sha512::finalize(std::span<std::byte> output) noexcept {
    if (output.size() < 64) return;
    pimpl->finalize(reinterpret_cast<uint8_t*>(output.data()));
}

void sha512::reset() noexcept {
    pimpl->reset();
}

void sha512::hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept {
    if (output.size() < 64) return;
    
#ifdef __APPLE__
    CC_SHA512(
        reinterpret_cast<const uint8_t*>(input.data()),
        static_cast<CC_LONG>(input.size()),
        reinterpret_cast<uint8_t*>(output.data())
    );
#endif
}

// ────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 implementation
// ────────────────────────────────────────────────────────────────────────────

class hmac_sha256::impl {
public:
#ifdef __APPLE__
    CCHmacContext ctx;
    bool finalized = false;
    
    impl() noexcept = default;
    
    impl(const uint8_t* key, size_t key_len) noexcept {
        CCHmacInit(&ctx, kCCHmacAlgSHA256, key, key_len);
    }
    
    void update(const uint8_t* data, size_t len) noexcept {
        if (!finalized) {
            CCHmacUpdate(&ctx, data, len);
        }
    }
    
    void finalize(uint8_t* output) noexcept {
        if (!finalized) {
            CCHmacFinal(&ctx, output);
            finalized = true;
        }
    }
    
    void reset(const uint8_t* key, size_t key_len) noexcept {
        CCHmacInit(&ctx, kCCHmacAlgSHA256, key, key_len);
        finalized = false;
    }
#endif
    
    utils::secure_vector<std::byte> key_copy;
};

hmac_sha256::hmac_sha256(std::span<const std::byte> key) noexcept 
    : pimpl(std::make_unique<impl>()) {
    pimpl->key_copy.reserve(key.size());
    pimpl->key_copy.insert(pimpl->key_copy.end(), key.begin(), key.end());
#ifdef __APPLE__
    pimpl = std::make_unique<impl>(
        reinterpret_cast<const uint8_t*>(key.data()), 
        key.size()
    );
    pimpl->key_copy = utils::secure_vector<std::byte>(key.begin(), key.end());
#endif
}

hmac_sha256::~hmac_sha256() = default;

void hmac_sha256::update(std::span<const std::byte> data) noexcept {
    pimpl->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void hmac_sha256::finalize(std::span<std::byte> output) noexcept {
    if (output.size() < 32) return;
    pimpl->finalize(reinterpret_cast<uint8_t*>(output.data()));
}

void hmac_sha256::reset() noexcept {
#ifdef __APPLE__
    pimpl->reset(
        reinterpret_cast<const uint8_t*>(pimpl->key_copy.data()),
        pimpl->key_copy.size()
    );
#endif
}

void hmac_sha256::hmac(
    std::span<const std::byte> key,
    std::span<const std::byte> input,
    std::span<std::byte> output
) noexcept {
    if (output.size() < 32) return;
    
#ifdef __APPLE__
    CCHmac(
        kCCHmacAlgSHA256,
        reinterpret_cast<const uint8_t*>(key.data()), key.size(),
        reinterpret_cast<const uint8_t*>(input.data()), input.size(),
        reinterpret_cast<uint8_t*>(output.data())
    );
#endif
}

// ────────────────────────────────────────────────────────────────────────────
// HMAC-SHA512 implementation
// ────────────────────────────────────────────────────────────────────────────

class hmac_sha512::impl {
public:
#ifdef __APPLE__
    CCHmacContext ctx;
    bool finalized = false;
    
    impl() noexcept = default;
    
    impl(const uint8_t* key, size_t key_len) noexcept {
        CCHmacInit(&ctx, kCCHmacAlgSHA512, key, key_len);
    }
    
    void update(const uint8_t* data, size_t len) noexcept {
        if (!finalized) {
            CCHmacUpdate(&ctx, data, len);
        }
    }
    
    void finalize(uint8_t* output) noexcept {
        if (!finalized) {
            CCHmacFinal(&ctx, output);
            finalized = true;
        }
    }
    
    void reset(const uint8_t* key, size_t key_len) noexcept {
        CCHmacInit(&ctx, kCCHmacAlgSHA512, key, key_len);
        finalized = false;
    }
#endif
    
    utils::secure_vector<std::byte> key_copy;
};

hmac_sha512::hmac_sha512(std::span<const std::byte> key) noexcept 
    : pimpl(std::make_unique<impl>()) {
    pimpl->key_copy.reserve(key.size());
    pimpl->key_copy.insert(pimpl->key_copy.end(), key.begin(), key.end());
#ifdef __APPLE__
    pimpl = std::make_unique<impl>(
        reinterpret_cast<const uint8_t*>(key.data()), 
        key.size()
    );
    pimpl->key_copy = utils::secure_vector<std::byte>(key.begin(), key.end());
#endif
}

hmac_sha512::~hmac_sha512() = default;

void hmac_sha512::update(std::span<const std::byte> data) noexcept {
    pimpl->update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

void hmac_sha512::finalize(std::span<std::byte> output) noexcept {
    if (output.size() < 64) return;
    pimpl->finalize(reinterpret_cast<uint8_t*>(output.data()));
}

void hmac_sha512::reset() noexcept {
#ifdef __APPLE__
    pimpl->reset(
        reinterpret_cast<const uint8_t*>(pimpl->key_copy.data()),
        pimpl->key_copy.size()
    );
#endif
}

void hmac_sha512::hmac(
    std::span<const std::byte> key,
    std::span<const std::byte> input,
    std::span<std::byte> output
) noexcept {
    if (output.size() < 64) return;
    
#ifdef __APPLE__
    CCHmac(
        kCCHmacAlgSHA512,
        reinterpret_cast<const uint8_t*>(key.data()), key.size(),
        reinterpret_cast<const uint8_t*>(input.data()), input.size(),
        reinterpret_cast<uint8_t*>(output.data())
    );
#endif
}

} // namespace psyfer::hash