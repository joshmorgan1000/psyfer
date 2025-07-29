/**
 * @file test_commoncrypto.cpp
 * @brief Test CommonCrypto AES performance
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <CommonCrypto/CommonCryptor.h>

int main() {
    std::cout << "=== CommonCrypto AES Test ===" << std::endl;
    
    // AES-256 key and IV
    uint8_t key[32];
    uint8_t iv[16];
    for (int i = 0; i < 32; ++i) key[i] = i;
    for (int i = 0; i < 16; ++i) iv[i] = i;
    
    // Test data
    std::vector<uint8_t> data(1024 * 1024); // 1MB
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = i & 0xFF;
    }
    
    std::vector<uint8_t> encrypted(data.size() + kCCBlockSizeAES128);
    size_t encrypted_len = 0;
    
    // Time encryption
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 100; ++i) {
        CCCryptorStatus status = CCCrypt(
            kCCEncrypt,
            kCCAlgorithmAES,
            kCCOptionPKCS7Padding,
            key, kCCKeySizeAES256,
            iv,
            data.data(), data.size(),
            encrypted.data(), encrypted.size(),
            &encrypted_len
        );
        
        if (status != kCCSuccess) {
            std::cerr << "Encryption failed: " << status << std::endl;
            return 1;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    double mb_per_sec = (100.0 * 1024.0 * 1024.0 / 1024.0 / 1024.0) / (duration.count() / 1000.0);
    std::cout << "CommonCrypto AES-256-CBC Performance: " << mb_per_sec << " MB/s" << std::endl;
    
    return 0;
}