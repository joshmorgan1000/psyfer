/**
 * @file ink_packet_patcher.cpp
 * @brief Post-build binary patcher for v3 hash-as-salt ink packet protection with embedded size
 */

#include "../include/ink_packet.hpp"
#include "../../include/encryption.hpp"
#include <fstream>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "../../third_party/BLAKE3/c/blake3.h"

namespace psyne::ink {

namespace fs = std::filesystem;

namespace {
    /**
     * @brief Create and manage OpenSSL cipher context
     */
    std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> make_cipher_ctx() {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        return {ctx, EVP_CIPHER_CTX_free};
    }
}

class InkPacketPatcher::Impl {
public:
    explicit Impl(const PatchConfig& cfg) : config(cfg) {}
    
    bool patch(std::string& error) {
        try {
            // Step 1: Analyze binary to find size placeholder
            auto info = analyze_binary(error);
            if (info.size_placeholder_offset == 0) {
                error = "Size placeholder not found in binary";
                return false;
            }
            
            // Step 2: Read original binary
            std::vector<uint8_t> original_binary;
            if (!read_binary(original_binary, error)) {
                return false;
            }
            
            // Step 3: Check if already protected
            if (info.has_existing_payload) {
                error = "Binary already contains ink packet protection";
                return false;
            }
            
            // Step 4: Read and encrypt payload using app hash
            std::vector<uint8_t> encrypted_payload;
            InkPacketMetadata metadata = {};
            if (!prepare_payload(original_binary, encrypted_payload, metadata, error)) {
                return false;
            }
            
            // Step 5: Create protected binary with patched size
            if (!create_protected_binary(original_binary, info, metadata, encrypted_payload, error)) {
                return false;
            }
            
            // Step 6: Verify the protected binary
            if (config.verify_after && !verify_protected_binary(error)) {
                return false;
            }
            
            return true;
            
        } catch (const std::exception& e) {
            error = "Patching failed: " + std::string(e.what());
            return false;
        }
    }
    
    BinaryInfo analyze_binary(std::string& error) {
        BinaryInfo info;
        
        std::ifstream file(config.binary_path, std::ios::binary);
        if (!file) {
            error = "Failed to open binary";
            return info;
        }
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0);
        
        info.total_size = file_size;
        
        // Read entire binary to search for size placeholder
        std::vector<uint8_t> data(file_size);
        file.read(reinterpret_cast<char*>(data.data()), file_size);
        
        // Look for size placeholder value (8-byte aligned)
        bool found_placeholder = false;
        
        for (size_t i = 0; i <= data.size() - 8; i += 8) {
            uint64_t potential_value = *reinterpret_cast<const uint64_t*>(&data[i]);
            
            if (potential_value == 0x5245484345414C50ULL) {
                // Found placeholder value - not yet protected
                info.size_placeholder_offset = i;
                info.has_existing_payload = false;
                info.app_size = file_size; // Entire file is application for now
                found_placeholder = true;
                
                std::cout << "Binary analysis (v3 hash-as-salt):\n";
                std::cout << "  Application size: " << info.app_size << " bytes\n";
                std::cout << "  Size placeholder found at offset: " << info.size_placeholder_offset << "\n";
                std::cout << "  Has existing payload: no\n";
                break;
            }
        }
        
        if (!found_placeholder) {
            // Check if we have the patched size field (8-byte aligned after guards)
            bool found_protected = false;
            
            // Look for the embedded size pattern (check for non-placeholder values)
            for (size_t i = 0; i <= data.size() - 8; i += 8) {
                uint64_t potential_size = *reinterpret_cast<const uint64_t*>(&data[i]);
                
                // Skip the placeholder pattern
                if (potential_size == 0x5245484345414C50ULL) continue;
                
                // Check if this looks like a reasonable app size
                if (potential_size > 0 && potential_size < file_size) {
                    // Verify we have metadata after this position
                    if (potential_size + sizeof(InkPacketMetadata) <= file_size) {
                        info.app_size = potential_size;
                        info.has_existing_payload = true;
                        info.size_placeholder_offset = i;
                        found_protected = true;
                        break;
                    }
                }
            }
            
            if (!found_protected) {
                // No placeholder and no existing protection found
                info.app_size = file_size;
                info.has_existing_payload = false;
                info.size_placeholder_offset = 0;
            }
            
            std::cout << "Binary analysis (v3 hash-as-salt):\n";
            std::cout << "  Application size: " << info.app_size << " bytes\n";
            std::cout << "  Has existing payload: " << (info.has_existing_payload ? "yes" : "no") << "\n";
            if (info.has_existing_payload) {
                std::cout << "  Total size: " << file_size << " bytes\n";
            }
        }
        
        return info;
    }
    
private:
    bool read_binary(std::vector<uint8_t>& data, std::string& error) {
        std::ifstream file(config.binary_path, std::ios::binary);
        if (!file) {
            error = "Failed to open binary";
            return false;
        }
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0);
        
        data.resize(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        return true;
    }
    
    std::vector<uint8_t> calculate_app_hash(const std::vector<uint8_t>& app_data) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, app_data.data(), app_data.size());
        
        std::vector<uint8_t> hash(32);
        blake3_hasher_finalize(&hasher, hash.data(), 32);
        return hash;
    }
    
    void derive_encryption_key(const std::vector<uint8_t>& hash, 
                              const InkPacketMetadata& metadata, 
                              uint8_t* key) {
        blake3_hasher kdf_hasher;
        blake3_hasher_init_keyed(&kdf_hasher, hash.data());
        
        const char* context = "ink_packet_v3_key_derivation";
        blake3_hasher_update(&kdf_hasher, context, strlen(context));
        
        // Include metadata in key derivation for additional entropy
        blake3_hasher_update(&kdf_hasher, reinterpret_cast<const uint8_t*>(&metadata), sizeof(metadata));
        
        // Include base key if provided
        if (!config.base_key.empty()) {
            blake3_hasher_update(&kdf_hasher, config.base_key.data(), config.base_key.size());
        }
        
        blake3_hasher_finalize(&kdf_hasher, key, 32);
    }
    
    bool read_payload(std::vector<uint8_t>& payload, std::string& error) {
        std::ifstream file(config.payload_path, std::ios::binary);
        if (!file) {
            error = "Failed to open payload file";
            return false;
        }
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0);
        
        payload.resize(size);
        file.read(reinterpret_cast<char*>(payload.data()), size);
        return true;
    }
    
    bool encrypt_aes_gcm(const uint8_t* key, const std::vector<uint8_t>& data, std::vector<uint8_t>& encrypted) {
        constexpr size_t IV_LEN = 12;
        constexpr size_t TAG_LEN = 16;
        
        // Generate IV
        std::array<uint8_t, IV_LEN> iv;
        RAND_bytes(iv.data(), iv.size());
        
        auto ctx = make_cipher_ctx();
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.data());
        
        encrypted.resize(IV_LEN + data.size() + TAG_LEN);
        std::copy(iv.begin(), iv.end(), encrypted.begin());
        
        int outl;
        EVP_EncryptUpdate(ctx.get(), encrypted.data() + IV_LEN, &outl, 
                         data.data(), data.size());
        EVP_EncryptFinal_ex(ctx.get(), nullptr, &outl);
        
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN,
                           encrypted.data() + IV_LEN + data.size());
        
        return true;
    }
    
    bool prepare_payload(const std::vector<uint8_t>& app_binary,
                        std::vector<uint8_t>& encrypted_payload,
                        InkPacketMetadata& metadata,
                        std::string& error) {
        // Read payload file
        std::vector<uint8_t> payload_data;
        if (!read_payload(payload_data, error)) {
            return false;
        }
        
        // Calculate hash of application binary
        auto app_hash = calculate_app_hash(app_binary);
        
        // Initialize metadata
        metadata.version = INK_PACKET_VERSION;
        metadata.hash_algo = config.hash_algo;
        metadata.enc_algo = config.enc_algo;
        metadata.flags = 0;
        std::memset(metadata.reserved, 0, sizeof(metadata.reserved));
        
        // Derive encryption key
        uint8_t key[32];
        derive_encryption_key(app_hash, metadata, key);
        
        // Encrypt payload
        if (!encrypt_aes_gcm(key, payload_data, encrypted_payload)) {
            error = "Failed to encrypt payload";
            OPENSSL_cleanse(key, sizeof(key));
            return false;
        }
        
        metadata.payload_size = encrypted_payload.size();
        
        // Calculate metadata checksum
        metadata.checksum = 0;
        metadata.checksum = crc32(reinterpret_cast<uint8_t*>(&metadata), sizeof(metadata));
        
        OPENSSL_cleanse(key, sizeof(key));
        return true;
    }
    
    bool create_protected_binary(const std::vector<uint8_t>& original,
                               const BinaryInfo& info,
                               const InkPacketMetadata& metadata,
                               const std::vector<uint8_t>& encrypted_payload,
                               std::string& error) {
        // Backup original if requested
        if (config.backup_original) {
            std::string backup_path = config.binary_path + ".backup";
            if (!fs::copy_file(config.binary_path, backup_path, 
                              fs::copy_options::overwrite_existing)) {
                error = "Failed to create backup";
                return false;
            }
        }
        
        // Build new binary with v3 layout: [App with patched size][Metadata][Encrypted Payload]
        std::vector<uint8_t> new_binary;
        size_t app_size = original.size(); // Size of application before adding payload
        size_t total_size = app_size + sizeof(InkPacketMetadata) + encrypted_payload.size();
        new_binary.reserve(total_size);
        
        // Step 1: Copy original binary and patch the size placeholder
        new_binary.insert(new_binary.end(), original.begin(), original.end());
        
        // Patch the size placeholder with actual app size
        if (info.size_placeholder_offset > 0 && 
            info.size_placeholder_offset + sizeof(uint64_t) <= new_binary.size()) {
            
            // Patch the app_size directly at the placeholder location
            uint64_t* size_ptr = reinterpret_cast<uint64_t*>(&new_binary[info.size_placeholder_offset]);
            *size_ptr = app_size;
            
            std::cout << "Patched app size at offset " << info.size_placeholder_offset 
                     << " with value " << app_size << "\n";
        } else {
            error = "Invalid size placeholder offset";
            return false;
        }
        
        // Step 2: Add metadata (no magic bytes in v3)
        new_binary.insert(new_binary.end(),
                         reinterpret_cast<const uint8_t*>(&metadata),
                         reinterpret_cast<const uint8_t*>(&metadata) + sizeof(metadata));
        
        // Step 3: Add encrypted payload
        new_binary.insert(new_binary.end(), encrypted_payload.begin(), encrypted_payload.end());
        
        // Write the protected binary
        std::ofstream out(config.binary_path, std::ios::binary);
        if (!out) {
            error = "Failed to write protected binary";
            return false;
        }
        
        out.write(reinterpret_cast<const char*>(new_binary.data()), new_binary.size());
        
        // Make executable
#ifndef _WIN32
        fs::permissions(config.binary_path,
                       fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                       fs::perm_options::add);
#endif
        
        std::cout << "Successfully created protected binary (v3 hash-as-salt)\n";
        std::cout << "  Application size: " << app_size << " bytes\n";
        std::cout << "  Metadata: " << sizeof(metadata) << " bytes\n";
        std::cout << "  Encrypted payload: " << encrypted_payload.size() << " bytes\n";
        std::cout << "  Total size: " << new_binary.size() << " bytes\n";
        std::cout << "  Hash-as-salt protection: ENABLED\n";
        std::cout << "  Size patched at offset: " << info.size_placeholder_offset << "\n";
        
        return true;
    }
    
    bool verify_protected_binary(std::string& error) {
        // Try to load and verify the protected binary
        InkPacketLoader loader(config.binary_path);
        
        if (!loader.verify()) {
            error = "Verification failed: " + loader.get_error();
            return false;
        }
        
        std::cout << "Protected binary verified successfully\n";
        return true;
    }
    
    uint32_t crc32(const uint8_t* data, size_t size) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < size; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        return ~crc;
    }
    
    PatchConfig config;
};

InkPacketPatcher::InkPacketPatcher(const PatchConfig& config) 
    : impl_(std::make_unique<Impl>(config)), config_(config) {}

InkPacketPatcher::~InkPacketPatcher() = default;

bool InkPacketPatcher::patch() {
    return impl_->patch(error_);
}

InkPacketPatcher::BinaryInfo InkPacketPatcher::analyze_binary() {
    std::string dummy_error;
    return impl_->analyze_binary(dummy_error);
}

} // namespace psyne::ink