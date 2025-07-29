/**
 * @file secure_key.cpp
 * @brief Implementation of secure key management
 */

#include <psyfer/utils/secure_key.hpp>
#include <psyfer/hash/sha.hpp>
#include <psyfer/crypto/aes256.hpp>

namespace psyfer::utils {

// Key derivation from password using SHA-256
template<size_t KeySize>
result<secure_key<KeySize>> secure_key<KeySize>::from_password(
    std::string_view password,
    std::span<const std::byte> salt,
    uint32_t iterations
) noexcept {
    // Simple PBKDF2-like derivation using SHA-256
    // In production, consider using a proper PBKDF2 or Argon2 implementation
    
    secure_buffer<32> derived;
    secure_buffer<32> temp;
    
    // Initial hash: SHA-256(password || salt)
    {
        hash::sha256 hasher;
        hasher.update(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(password.data()),
            password.size()
        ));
        hasher.update(salt);
        hasher.finalize(derived.span());
    }
    
    // Iterate
    for (uint32_t i = 0; i < iterations; ++i) {
        // Use HMAC-SHA256 for key derivation iterations
        hash::hmac_sha256::hmac(derived.span(), 
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&i),
                sizeof(i)
            ),
            temp.span());
        
        // XOR into result
        for (size_t j = 0; j < 32; ++j) {
            derived.data()[j] ^= temp.data()[j];
        }
    }
    
    // Extract the required key size
    secure_key<KeySize> key;
    if constexpr (KeySize <= 32) {
        std::memcpy(key.key_.data(), derived.data(), KeySize);
    } else {
        // For larger keys, use multiple rounds of SHA-256
        secure_buffer<KeySize> extended;
        size_t offset = 0;
        uint32_t counter = 0;
        
        while (offset < KeySize) {
            hash::sha256 hasher;
            hasher.update(derived.span());
            hasher.update(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&counter),
                sizeof(counter)
            ));
            
            std::array<std::byte, 32> chunk;
            hasher.finalize(chunk);
            
            size_t to_copy = std::min(size_t(32), KeySize - offset);
            std::memcpy(extended.data() + offset, chunk.data(), to_copy);
            offset += to_copy;
            counter++;
        }
        
        key.key_.fill(extended.span());
    }
    
    key.created_at_ = std::chrono::steady_clock::now();
    return key;
}

// Export key with protection
template<size_t KeySize>
result<secure_vector<std::byte>> secure_key<KeySize>::export_protected(
    std::span<const std::byte, 32> protection_key
) const noexcept {
    // Generate random nonce
    auto nonce_result = secure_random::generate_nonce<12>();
    if (!nonce_result) {
        return std::unexpected(nonce_result.error());
    }
    
    // Prepare output: nonce || encrypted_key || tag
    secure_vector<std::byte> output;
    output.reserve(12 + KeySize + 16);
    
    // Copy nonce
    output.insert(output.end(), 
                  nonce_result.value().begin(), 
                  nonce_result.value().end());
    
    // Copy key data to encrypt
    output.insert(output.end(),
                  key_.data(),
                  key_.data() + KeySize);
    
    // Encrypt in place
    std::array<std::byte, 16> tag;
    auto ec = crypto::aes256_gcm::encrypt_oneshot(
        std::span<std::byte>(output.data() + 12, KeySize),
        protection_key,
        nonce_result.value(),
        tag,
        {}
    );
    
    if (ec) {
        return std::unexpected(ec);
    }
    
    // Append tag
    output.insert(output.end(), tag.begin(), tag.end());
    
    return output;
}

// Import protected key
template<size_t KeySize>
result<secure_key<KeySize>> secure_key<KeySize>::import_protected(
    std::span<const std::byte> encrypted_data,
    std::span<const std::byte, 32> protection_key
) noexcept {
    // Check minimum size: nonce(12) + key(KeySize) + tag(16)
    if (encrypted_data.size() != 12 + KeySize + 16) {
        return std::unexpected(make_error_code(error_code::invalid_buffer_size));
    }
    
    // Extract components
    std::array<std::byte, 12> nonce;
    std::memcpy(nonce.data(), encrypted_data.data(), 12);
    
    std::array<std::byte, 16> tag;
    std::memcpy(tag.data(), encrypted_data.data() + 12 + KeySize, 16);
    
    // Copy encrypted key data
    secure_buffer<KeySize> key_data;
    std::memcpy(key_data.data(), encrypted_data.data() + 12, KeySize);
    
    // Decrypt
    auto ec = crypto::aes256_gcm::decrypt_oneshot(
        key_data.span(),
        protection_key,
        nonce,
        tag,
        {}
    );
    
    if (ec) {
        return std::unexpected(ec);
    }
    
    // Create key from decrypted data
    return from_bytes(key_data.span());
}

// Explicit instantiations
template class secure_key<16>;
template class secure_key<24>;
template class secure_key<32>;
template class secure_key<48>;
template class secure_key<64>;
template class secure_key<128>;
template class secure_key<256>;

} // namespace psyfer::utils