/**
 * @file test_preprocessor2.cpp
 * @brief Test preprocessor in aes256.cpp context
 */

#include <iostream>

// Simulate the exact includes from aes256.cpp
#ifdef __AES__
#include <wmmintrin.h>  // AES-NI intrinsics
#include <emmintrin.h>  // SSE2
#include <smmintrin.h>  // SSE4.1
#endif

#ifdef __aarch64__
#ifdef __ARM_FEATURE_CRYPTO
#include <arm_neon.h>
#endif
#endif

bool test_aes_ni_available() noexcept {
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    std::cout << "In ARM64 crypto path" << std::endl;
    return true;
    #elif defined(__AES__)
    std::cout << "In x86_64 AES-NI path" << std::endl;
    return false;  // Simplified
    #else
    std::cout << "In fallback path" << std::endl;
    return false;
    #endif
}

int main() {
    std::cout << "Testing preprocessor paths:" << std::endl;
    
    #ifdef __aarch64__
    std::cout << "__aarch64__ = DEFINED" << std::endl;
    #endif
    
    #ifdef __ARM_FEATURE_CRYPTO
    std::cout << "__ARM_FEATURE_CRYPTO = DEFINED" << std::endl;
    #endif
    
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    std::cout << "ARM64 crypto condition = TRUE" << std::endl;
    #else
    std::cout << "ARM64 crypto condition = FALSE" << std::endl;
    #endif
    
    bool result = test_aes_ni_available();
    std::cout << "Function returned: " << (result ? "true" : "false") << std::endl;
    
    return 0;
}