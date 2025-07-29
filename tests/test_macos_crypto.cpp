/**
 * @file test_macos_crypto.cpp
 * @brief Test what crypto acceleration is available on macOS
 */

#include <iostream>
#include <Security/Security.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

#ifdef __APPLE__
#include <Availability.h>
#endif

int main() {
    std::cout << "=== macOS Crypto Capabilities ===" << std::endl;
    
    // Check what's available in CommonCrypto
    std::cout << "\nCommonCrypto supports:" << std::endl;
    std::cout << "- AES (hardware accelerated)" << std::endl;
    std::cout << "- SHA1/SHA2 (hardware accelerated)" << std::endl;
    std::cout << "- DES/3DES" << std::endl;
    std::cout << "- RC4" << std::endl;
    std::cout << "- Blowfish" << std::endl;
    std::cout << "- CAST" << std::endl;
    
    // Check Security framework
    std::cout << "\nSecurity.framework supports:" << std::endl;
    std::cout << "- RSA" << std::endl;
    std::cout << "- ECDSA (P-256, P-384, P-521)" << std::endl;
    std::cout << "- No Curve25519 support in CommonCrypto or Security.framework" << std::endl;
    
    std::cout << "\nFor X25519/Curve25519 on macOS:" << std::endl;
    std::cout << "- CryptoKit (Swift only, iOS 13+/macOS 10.15+)" << std::endl;
    std::cout << "- No C/C++ API available" << std::endl;
    std::cout << "- Must use software implementation or external library" << std::endl;
    
    // Check ARM64 crypto extensions
#ifdef __ARM_FEATURE_CRYPTO
    std::cout << "\nARM64 Crypto Extensions: Available" << std::endl;
    std::cout << "- Can be used for accelerating field arithmetic" << std::endl;
#else
    std::cout << "\nARM64 Crypto Extensions: Not detected" << std::endl;
#endif
    
    return 0;
}