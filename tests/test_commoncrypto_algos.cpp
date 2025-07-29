/**
 * @file test_commoncrypto_algos.cpp
 * @brief Check what algorithms CommonCrypto supports
 */

#include <iostream>
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>

// Check if newer headers exist
#ifdef __has_include
  #if __has_include(<CommonCrypto/CommonRandom.h>)
    #include <CommonCrypto/CommonRandom.h>
    #define HAS_COMMON_RANDOM 1
  #endif
  #if __has_include(<CommonCrypto/CommonKeyDerivation.h>)
    #include <CommonCrypto/CommonKeyDerivation.h>
    #define HAS_KEY_DERIVATION 1
  #endif
#endif

int main() {
    std::cout << "=== CommonCrypto Algorithm Support ===" << std::endl;
    
    std::cout << "\nHash Algorithms:" << std::endl;
    std::cout << "- MD5: " << CC_MD5_DIGEST_LENGTH << " bytes" << std::endl;
    std::cout << "- SHA1: " << CC_SHA1_DIGEST_LENGTH << " bytes" << std::endl;
    std::cout << "- SHA224: " << CC_SHA224_DIGEST_LENGTH << " bytes" << std::endl;
    std::cout << "- SHA256: " << CC_SHA256_DIGEST_LENGTH << " bytes" << std::endl;
    std::cout << "- SHA384: " << CC_SHA384_DIGEST_LENGTH << " bytes" << std::endl;
    std::cout << "- SHA512: " << CC_SHA512_DIGEST_LENGTH << " bytes" << std::endl;
    
    std::cout << "\nSymmetric Ciphers (from CCAlgorithm enum):" << std::endl;
    std::cout << "- AES128: " << kCCAlgorithmAES128 << " (deprecated, use AES)" << std::endl;
    std::cout << "- AES: " << kCCAlgorithmAES << std::endl;
    std::cout << "- DES: " << kCCAlgorithmDES << std::endl;
    std::cout << "- 3DES: " << kCCAlgorithm3DES << std::endl;
    std::cout << "- CAST: " << kCCAlgorithmCAST << std::endl;
    std::cout << "- RC4: " << kCCAlgorithmRC4 << std::endl;
    std::cout << "- RC2: " << kCCAlgorithmRC2 << std::endl;
    std::cout << "- Blowfish: " << kCCAlgorithmBlowfish << std::endl;
    
    // Check for ChaCha20
    #ifdef kCCAlgorithmChaCha20
    std::cout << "- ChaCha20: SUPPORTED" << std::endl;
    #else
    std::cout << "- ChaCha20: NOT FOUND in CommonCrypto" << std::endl;
    #endif
    
    // Check for Poly1305
    #ifdef kCCAlgorithmPoly1305
    std::cout << "- Poly1305: SUPPORTED" << std::endl;
    #else
    std::cout << "- Poly1305: NOT FOUND in CommonCrypto" << std::endl;
    #endif
    
    // Check for BLAKE
    #ifdef CC_BLAKE2B_DIGEST_LENGTH
    std::cout << "- BLAKE2b: " << CC_BLAKE2B_DIGEST_LENGTH << " bytes" << std::endl;
    #else
    std::cout << "- BLAKE2: NOT FOUND in CommonCrypto" << std::endl;
    #endif
    
    #ifdef CC_BLAKE3_DIGEST_LENGTH
    std::cout << "- BLAKE3: SUPPORTED" << std::endl;
    #else
    std::cout << "- BLAKE3: NOT FOUND in CommonCrypto" << std::endl;
    #endif
    
    std::cout << "\nOther Features:" << std::endl;
    #ifdef HAS_COMMON_RANDOM
    std::cout << "- CommonRandom: AVAILABLE" << std::endl;
    #endif
    #ifdef HAS_KEY_DERIVATION
    std::cout << "- Key Derivation (PBKDF2): AVAILABLE" << std::endl;
    #endif
    
    return 0;
}