/**
 * @file test_cryptokit.cpp
 * @brief Test CryptoKit availability and performance (macOS 10.15+, iOS 13.0+)
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <Availability.h>

// CryptoKit requires macOS 10.15+ or iOS 13.0+
#if __has_include(<CryptoKit/CryptoKit.h>) && \
    ((TARGET_OS_MAC && __MAC_OS_X_VERSION_MAX_ALLOWED >= 101500) || \
     (TARGET_OS_IOS && __IPHONE_OS_VERSION_MAX_ALLOWED >= 130000))
#define HAS_CRYPTOKIT 1
#include <CryptoKit/CryptoKit.h>
#endif
#endif

int main() {
    std::cout << "=== CryptoKit Availability Test ===" << std::endl;
    
#ifdef HAS_CRYPTOKIT
    std::cout << "CryptoKit: AVAILABLE" << std::endl;
    std::cout << "\nNote: CryptoKit is a Swift framework and requires" << std::endl;
    std::cout << "Swift/Objective-C++ bridge to use from C++." << std::endl;
    std::cout << "It provides:" << std::endl;
    std::cout << "- AES-GCM" << std::endl;
    std::cout << "- ChaCha20-Poly1305" << std::endl;
    std::cout << "- SHA256, SHA384, SHA512" << std::endl;
    std::cout << "- HMAC" << std::endl;
    std::cout << "- Curve25519 (X25519, Ed25519)" << std::endl;
    std::cout << "- P256, P384, P521" << std::endl;
    std::cout << "- HKDF" << std::endl;
    std::cout << "\nHowever, using CryptoKit from C++ requires:" << std::endl;
    std::cout << "1. Creating an Objective-C++ wrapper (.mm file)" << std::endl;
    std::cout << "2. Using Swift/ObjC bridge headers" << std::endl;
    std::cout << "3. More complex build configuration" << std::endl;
#else
    std::cout << "CryptoKit: NOT AVAILABLE" << std::endl;
    std::cout << "\nCryptoKit requires:" << std::endl;
    std::cout << "- macOS 10.15+ or iOS 13.0+" << std::endl;
    std::cout << "- Swift runtime" << std::endl;
    std::cout << "- Xcode project or special CMake configuration" << std::endl;
#endif
    
    std::cout << "\nFor C++ projects, CommonCrypto is recommended as it:" << std::endl;
    std::cout << "- Has a pure C API" << std::endl;
    std::cout << "- Is available on all Apple platforms" << std::endl;
    std::cout << "- Provides hardware acceleration" << std::endl;
    std::cout << "- No Swift/ObjC bridge overhead" << std::endl;
    
    return 0;
}