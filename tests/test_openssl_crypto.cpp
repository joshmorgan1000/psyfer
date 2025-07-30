/**
 * @file test_openssl_crypto.cpp
 * @brief Test OpenSSL implementations of AES-GCM and ChaCha20-Poly1305
 */

#include <psyfer.hpp>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>

#ifdef HAVE_OPENSSL

void test_aes256_gcm_openssl() {
    std::cout << "\n=== Testing AES-256-GCM (OpenSSL backend) ===\n";
    
    // Test vectors from NIST
    std::array<std::byte, 32> key = {
        std::byte{0xfe}, std::byte{0xff}, std::byte{0xe9}, std::byte{0x92},
        std::byte{0x86}, std::byte{0x65}, std::byte{0x73}, std::byte{0x1c},
        std::byte{0x6d}, std::byte{0x6a}, std::byte{0x8f}, std::byte{0x94},
        std::byte{0x67}, std::byte{0x30}, std::byte{0x83}, std::byte{0x08},
        std::byte{0xfe}, std::byte{0xff}, std::byte{0xe9}, std::byte{0x92},
        std::byte{0x86}, std::byte{0x65}, std::byte{0x73}, std::byte{0x1c},
        std::byte{0x6d}, std::byte{0x6a}, std::byte{0x8f}, std::byte{0x94},
        std::byte{0x67}, std::byte{0x30}, std::byte{0x83}, std::byte{0x08}
    };
    
    std::array<std::byte, 12> nonce = {
        std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe},
        std::byte{0xfa}, std::byte{0xce}, std::byte{0xdb}, std::byte{0xad},
        std::byte{0xde}, std::byte{0xca}, std::byte{0xf8}, std::byte{0x88}
    };
    
    // Test with data
    std::vector<std::byte> plaintext = {
        std::byte{0xd9}, std::byte{0x31}, std::byte{0x32}, std::byte{0x25},
        std::byte{0xf8}, std::byte{0x84}, std::byte{0x06}, std::byte{0xe5},
        std::byte{0xa5}, std::byte{0x59}, std::byte{0x09}, std::byte{0xc5},
        std::byte{0xaf}, std::byte{0xf5}, std::byte{0x26}, std::byte{0x9a},
        std::byte{0x86}, std::byte{0xa7}, std::byte{0xa9}, std::byte{0x53},
        std::byte{0x15}, std::byte{0x34}, std::byte{0xf7}, std::byte{0xda},
        std::byte{0x2e}, std::byte{0x4c}, std::byte{0x30}, std::byte{0x3d},
        std::byte{0x8a}, std::byte{0x31}, std::byte{0x8a}, std::byte{0x72},
        std::byte{0x1c}, std::byte{0x3c}, std::byte{0x0c}, std::byte{0x95},
        std::byte{0x95}, std::byte{0x68}, std::byte{0x09}, std::byte{0x53},
        std::byte{0x2f}, std::byte{0xcf}, std::byte{0x0e}, std::byte{0x24},
        std::byte{0x49}, std::byte{0xa6}, std::byte{0xb5}, std::byte{0x25},
        std::byte{0xb1}, std::byte{0x6a}, std::byte{0xed}, std::byte{0xf5},
        std::byte{0xaa}, std::byte{0x0d}, std::byte{0xe6}, std::byte{0x57},
        std::byte{0xba}, std::byte{0x63}, std::byte{0x7b}, std::byte{0x39}
    };
    
    std::vector<std::byte> aad = {
        std::byte{0xfe}, std::byte{0xed}, std::byte{0xfa}, std::byte{0xce},
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef},
        std::byte{0xfe}, std::byte{0xed}, std::byte{0xfa}, std::byte{0xce},
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef},
        std::byte{0xab}, std::byte{0xad}, std::byte{0xda}, std::byte{0xd2}
    };
    
    // Expected values
    std::vector<uint8_t> expected_ciphertext = {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
    };
    
    std::vector<uint8_t> expected_tag = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
    };
    
    // Test encryption
    psyfer::crypto::aes256_gcm cipher;
    std::vector<std::byte> data = plaintext;
    std::array<std::byte, 16> tag;
    
    auto result = cipher.encrypt(data, key, nonce, tag, aad);
    
    if (result) {
        std::cout << "Encryption failed: " << result.message() << "\n";
        return;
    }
    
    std::cout << "OpenSSL Encryption succeeded\n";
    
    // Check ciphertext
    bool ciphertext_match = true;
    for (size_t i = 0; i < expected_ciphertext.size(); ++i) {
        if (static_cast<uint8_t>(data[i]) != expected_ciphertext[i]) {
            ciphertext_match = false;
            break;
        }
    }
    
    // Check tag
    bool tag_match = true;
    for (size_t i = 0; i < expected_tag.size(); ++i) {
        if (static_cast<uint8_t>(tag[i]) != expected_tag[i]) {
            tag_match = false;
            break;
        }
    }
    
    std::cout << "Ciphertext matches expected: " << (ciphertext_match ? "YES" : "NO") << "\n";
    std::cout << "Tag matches expected: " << (tag_match ? "YES" : "NO") << "\n";
    
    if (!tag_match) {
        std::cout << "Expected tag: ";
        for (auto b : expected_tag) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        std::cout << "\n";
        
        std::cout << "Got tag:      ";
        for (auto b : tag) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(static_cast<uint8_t>(b));
        }
        std::cout << "\n";
    }
    
    // Test decryption
    auto result2 = cipher.decrypt(data, key, nonce, tag, aad);
    
    if (result2) {
        std::cout << "Decryption failed: " << result2.message() << "\n";
        return;
    }
    
    // Check plaintext
    bool plaintext_match = true;
    for (size_t i = 0; i < plaintext.size(); ++i) {
        if (data[i] != plaintext[i]) {
            plaintext_match = false;
            break;
        }
    }
    
    std::cout << "Decryption succeeded, plaintext matches: " << (plaintext_match ? "YES" : "NO") << "\n";
}

void test_chacha20_poly1305_openssl() {
    std::cout << "\n=== Testing ChaCha20-Poly1305 (OpenSSL backend) ===\n";
    
    // Test vectors from RFC 8439
    std::array<std::byte, 32> key;
    std::array<std::byte, 12> nonce;
    
    // Key: 00 01 02 ... 1f
    for (int i = 0; i < 32; ++i) {
        key[i] = static_cast<std::byte>(i);
    }
    
    // Nonce: 00 00 00 00 00 00 00 00 00 00 00 02
    std::fill(nonce.begin(), nonce.end(), std::byte{0});
    nonce[11] = std::byte{2};
    
    // Plaintext
    std::vector<std::byte> plaintext = {
        std::byte{0x4c}, std::byte{0x61}, std::byte{0x64}, std::byte{0x69},
        std::byte{0x65}, std::byte{0x73}, std::byte{0x20}, std::byte{0x61},
        std::byte{0x6e}, std::byte{0x64}, std::byte{0x20}, std::byte{0x47},
        std::byte{0x65}, std::byte{0x6e}, std::byte{0x74}, std::byte{0x6c},
        std::byte{0x65}, std::byte{0x6d}, std::byte{0x65}, std::byte{0x6e},
        std::byte{0x20}, std::byte{0x6f}, std::byte{0x66}, std::byte{0x20},
        std::byte{0x74}, std::byte{0x68}, std::byte{0x65}, std::byte{0x20},
        std::byte{0x63}, std::byte{0x6c}, std::byte{0x61}, std::byte{0x73},
        std::byte{0x73}, std::byte{0x20}, std::byte{0x6f}, std::byte{0x66},
        std::byte{0x20}, std::byte{0x27}, std::byte{0x39}, std::byte{0x39},
        std::byte{0x3a}, std::byte{0x20}, std::byte{0x49}, std::byte{0x66},
        std::byte{0x20}, std::byte{0x49}, std::byte{0x20}, std::byte{0x63},
        std::byte{0x6f}, std::byte{0x75}, std::byte{0x6c}, std::byte{0x64},
        std::byte{0x20}, std::byte{0x6f}, std::byte{0x66}, std::byte{0x66},
        std::byte{0x65}, std::byte{0x72}, std::byte{0x20}, std::byte{0x79},
        std::byte{0x6f}, std::byte{0x75}, std::byte{0x20}, std::byte{0x6f},
        std::byte{0x6e}, std::byte{0x6c}, std::byte{0x79}, std::byte{0x20},
        std::byte{0x6f}, std::byte{0x6e}, std::byte{0x65}, std::byte{0x20},
        std::byte{0x74}, std::byte{0x69}, std::byte{0x70}, std::byte{0x20},
        std::byte{0x66}, std::byte{0x6f}, std::byte{0x72}, std::byte{0x20},
        std::byte{0x74}, std::byte{0x68}, std::byte{0x65}, std::byte{0x20},
        std::byte{0x66}, std::byte{0x75}, std::byte{0x74}, std::byte{0x75},
        std::byte{0x72}, std::byte{0x65}, std::byte{0x2c}, std::byte{0x20},
        std::byte{0x73}, std::byte{0x75}, std::byte{0x6e}, std::byte{0x73},
        std::byte{0x63}, std::byte{0x72}, std::byte{0x65}, std::byte{0x65},
        std::byte{0x6e}, std::byte{0x20}, std::byte{0x77}, std::byte{0x6f},
        std::byte{0x75}, std::byte{0x6c}, std::byte{0x64}, std::byte{0x20},
        std::byte{0x62}, std::byte{0x65}, std::byte{0x20}, std::byte{0x69},
        std::byte{0x74}, std::byte{0x2e}
    };
    
    std::vector<std::byte> aad;  // Empty AAD
    
    // Expected values from RFC 8439
    std::vector<uint8_t> expected_ciphertext = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    
    std::vector<uint8_t> expected_tag = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    
    // Test encryption
    psyfer::crypto::chacha20_poly1305 cipher;
    std::vector<std::byte> data = plaintext;
    std::array<std::byte, 16> tag;
    
    auto result = cipher.encrypt(data, key, nonce, tag, aad);
    
    if (result) {
        std::cout << "Encryption failed: " << result.message() << "\n";
        return;
    }
    
    std::cout << "OpenSSL Encryption succeeded\n";
    
    // Check ciphertext
    bool ciphertext_match = true;
    for (size_t i = 0; i < expected_ciphertext.size(); ++i) {
        if (static_cast<uint8_t>(data[i]) != expected_ciphertext[i]) {
            ciphertext_match = false;
            break;
        }
    }
    
    // Check tag
    bool tag_match = true;
    for (size_t i = 0; i < expected_tag.size(); ++i) {
        if (static_cast<uint8_t>(tag[i]) != expected_tag[i]) {
            tag_match = false;
            break;
        }
    }
    
    std::cout << "Ciphertext matches expected: " << (ciphertext_match ? "YES" : "NO") << "\n";
    std::cout << "Tag matches expected: " << (tag_match ? "YES" : "NO") << "\n";
    
    if (!tag_match) {
        std::cout << "Expected tag: ";
        for (auto b : expected_tag) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        std::cout << "\n";
        
        std::cout << "Got tag:      ";
        for (auto b : tag) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(static_cast<uint8_t>(b));
        }
        std::cout << "\n";
    }
    
    // Test decryption
    auto result2 = cipher.decrypt(data, key, nonce, tag, aad);
    
    if (result2) {
        std::cout << "Decryption failed: " << result2.message() << "\n";
        return;
    }
    
    // Check plaintext
    bool plaintext_match = true;
    for (size_t i = 0; i < plaintext.size(); ++i) {
        if (data[i] != plaintext[i]) {
            plaintext_match = false;
            break;
        }
    }
    
    std::cout << "Decryption succeeded, plaintext matches: " << (plaintext_match ? "YES" : "NO") << "\n";
}

#endif // HAVE_OPENSSL

int main() {
#ifdef HAVE_OPENSSL
    test_aes256_gcm_openssl();
    test_chacha20_poly1305_openssl();
    std::cout << "\n✅ All OpenSSL tests completed!\n";
#else
    std::cout << "OpenSSL support not enabled. Please rebuild with OpenSSL.\n";
#endif
    return 0;
}