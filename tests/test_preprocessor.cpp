/**
 * @file test_preprocessor.cpp
 * @brief Test preprocessor definitions
 */

#include <iostream>

int main() {
    std::cout << "Preprocessor test:" << std::endl;
    
    #ifdef __aarch64__
    std::cout << "__aarch64__ = DEFINED" << std::endl;
    #else
    std::cout << "__aarch64__ = NOT DEFINED" << std::endl;
    #endif
    
    #ifdef __ARM_FEATURE_CRYPTO
    std::cout << "__ARM_FEATURE_CRYPTO = DEFINED" << std::endl;
    #else
    std::cout << "__ARM_FEATURE_CRYPTO = NOT DEFINED" << std::endl;
    #endif
    
    #ifdef __AES__
    std::cout << "__AES__ = DEFINED" << std::endl;
    #else
    std::cout << "__AES__ = NOT DEFINED" << std::endl;
    #endif
    
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    std::cout << "ARM64 crypto check = TRUE" << std::endl;
    #else
    std::cout << "ARM64 crypto check = FALSE" << std::endl;
    #endif
    
    return 0;
}