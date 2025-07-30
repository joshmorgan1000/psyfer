/**
 * @file aes256_commoncrypto.cpp
 * @brief AES-256 implementation using CommonCrypto (macOS/iOS)
 */

#include <psyfer.hpp>

#ifdef __APPLE__
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonCrypto.h>

namespace psyfer {

/**
 * @brief Check if CommonCrypto is available (always true on Apple platforms)
 */
bool aes_commoncrypto_available() noexcept {
    return true;
}

/**
 * @brief AES-256 key expansion using CommonCrypto
 * Note: CommonCrypto handles key expansion internally
 */
void aes256_key_expansion_cc(const uint8_t* key, uint8_t* round_keys) {
    // CommonCrypto handles key expansion internally
    // Just copy the key for interface compatibility
    std::memcpy(round_keys, key, 32);
}

/**
 * @brief Encrypt a block using CommonCrypto
 */
void aes256_encrypt_block_cc(const uint8_t* key, uint8_t* block) {
    size_t bytes_encrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionECBMode,  // ECB mode for single block
        key, kCCKeySizeAES256,
        nullptr,  // No IV for ECB
        block, kCCBlockSizeAES128,
        block, kCCBlockSizeAES128,
        &bytes_encrypted
    );
    
    if (status != kCCSuccess) {
        // Handle error - for now, leave block unchanged
    }
}

/**
 * @brief Decrypt a block using CommonCrypto
 */
void aes256_decrypt_block_cc(const uint8_t* key, uint8_t* block) {
    size_t bytes_decrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionECBMode,  // ECB mode for single block
        key, kCCKeySizeAES256,
        nullptr,  // No IV for ECB
        block, kCCBlockSizeAES128,
        block, kCCBlockSizeAES128,
        &bytes_decrypted
    );
    
    if (status != kCCSuccess) {
        // Handle error - for now, leave block unchanged
    }
}

/**
 * @brief GCM implementation using CommonCrypto
 * Note: CommonCrypto doesn't have native GCM support in the public API
 * For production use, consider using Security framework's SecKeyCreateEncryptedData
 * or implementing GCM on top of ECB mode
 */
class aes256_gcm_cc {
private:
    CCCryptorRef cryptor = nullptr;
    
public:
    explicit aes256_gcm_cc(const uint8_t* key) {
        CCCryptorCreate(
            kCCEncrypt,
            kCCAlgorithmAES,
            kCCOptionECBMode,
            key, kCCKeySizeAES256,
            nullptr,
            &cryptor
        );
    }
    
    ~aes256_gcm_cc() {
        if (cryptor) {
            CCCryptorRelease(cryptor);
        }
    }
    
    void encrypt_block(uint8_t* block) {
        if (!cryptor) return;
        
        size_t bytes_encrypted = 0;
        CCCryptorUpdate(
            cryptor,
            block, kCCBlockSizeAES128,
            block, kCCBlockSizeAES128,
            &bytes_encrypted
        );
    }
};

} // namespace psyfer

#endif // __APPLE__