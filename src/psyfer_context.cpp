/**
 * @file psyfer_context.cpp
 * @brief Implementation of PsyferContext unified crypto interface
 */

#include <psyfer.hpp>
#include <cstring>

namespace psyfer {

// Static factory method to create a new context with default config
result<std::unique_ptr<PsyferContext>> PsyferContext::create() noexcept {
    return create(Config{});
}

// Static factory method to create a new context
result<std::unique_ptr<PsyferContext>> PsyferContext::create(const Config& config) noexcept {
    auto ctx = std::unique_ptr<PsyferContext>(new PsyferContext());
    
    ctx->identity_name_ = config.identity_name;
    ctx->created_at_ = std::chrono::system_clock::now();
    ctx->rotation_period_ = config.key_rotation_period;
    
    // Initialize all keys
    auto err = ctx->initialize_keys(config);
    if (err) {
        return std::unexpected(err);
    }
    
    return ctx;
}

// Initialize all cryptographic keys
std::error_code PsyferContext::initialize_keys(const Config& config) noexcept {
    // Generate master key
    if (config.generate_encryption_key) {
        auto key_result = secure_key_256::generate();
        if (!key_result) {
            return key_result.error();
        }
        master_key_ = std::move(key_result.value());
    }
    
    // Generate X25519 key pair for key exchange
    if (config.generate_key_exchange) {
        auto kp_result = x25519::key_pair::generate();
        if (!kp_result) {
            return kp_result.error();
        }
        x25519_keypair_ = std::move(kp_result.value());
    }
    
    // Generate Ed25519 key pair for signatures
    if (config.generate_signing_key) {
        auto kp_result = ed25519::generate_key_pair();
        if (!kp_result) {
            return kp_result.error();
        }
        ed25519_keypair_ = std::move(kp_result.value());
    }
    
    // Derive subkeys from master key
    return derive_subkeys();
}

// Derive HMAC and psy-c keys from master key
std::error_code PsyferContext::derive_subkeys() noexcept {
    // Derive HMAC key
    std::array<std::byte, 32> hmac_key_data;
    auto err = hkdf::derive_sha256(
        master_key_.span(),
        std::span<const std::byte>{},  // No salt
        std::as_bytes(std::span("psyfer-hmac-key")),
        hmac_key_data
    );
    if (err) return err;
    hmac_key_ = secure_key_256::from_bytes(hmac_key_data);
    
    // Derive psy-c key
    std::array<std::byte, 32> psy_key_data;
    err = hkdf::derive_sha256(
        master_key_.span(),
        std::span<const std::byte>{},  // No salt
        std::as_bytes(std::span("psyfer-psy-c-key")),
        psy_key_data
    );
    if (err) return err;
    psy_key_ = secure_key_256::from_bytes(psy_key_data);
    
    return {};
}

// ===== Symmetric Encryption Implementation =====

result<PsyferContext::EncryptResult> PsyferContext::encrypt_aes(
    std::span<std::byte> plaintext,
    std::span<const std::byte> aad
) noexcept {
    EncryptResult result;
    
    // Generate fresh nonce
    auto err = secure_random::generate(result.nonce);
    if (err) return std::unexpected(err);
    
    // Encrypt in place
    aes256_gcm cipher;
    err = cipher.encrypt(plaintext, master_key_.span(), result.nonce, result.tag, aad);
    if (err) return std::unexpected(err);
    
    return result;
}

std::error_code PsyferContext::decrypt_aes(
    std::span<std::byte> ciphertext,
    std::span<const std::byte, 12> nonce,
    std::span<const std::byte, 16> tag,
    std::span<const std::byte> aad
) noexcept {
    aes256_gcm cipher;
    return cipher.decrypt(ciphertext, master_key_.span(), nonce, tag, aad);
}

result<std::vector<std::byte>> PsyferContext::encrypt_string(
    std::string_view plaintext
) noexcept {
    // Allocate buffer for nonce + tag + ciphertext
    std::vector<std::byte> buffer(12 + 16 + plaintext.size());
    
    // Copy plaintext to end of buffer
    std::memcpy(buffer.data() + 28, plaintext.data(), plaintext.size());
    
    // Encrypt in place
    std::span<std::byte> data(buffer.data() + 28, plaintext.size());
    auto result = encrypt_aes(data);
    if (!result) return std::unexpected(result.error());
    
    // Copy nonce and tag to beginning
    std::memcpy(buffer.data(), result->nonce.data(), 12);
    std::memcpy(buffer.data() + 12, result->tag.data(), 16);
    
    return buffer;
}

result<std::string> PsyferContext::decrypt_string(
    std::span<const std::byte> ciphertext
) noexcept {
    if (ciphertext.size() < 28) {
        return std::unexpected(make_error_code(error_code::invalid_buffer_size));
    }
    
    // Extract nonce and tag
    std::array<std::byte, 12> nonce;
    std::array<std::byte, 16> tag;
    std::memcpy(nonce.data(), ciphertext.data(), 12);
    std::memcpy(tag.data(), ciphertext.data() + 12, 16);
    
    // Copy ciphertext
    std::vector<std::byte> plaintext(ciphertext.begin() + 28, ciphertext.end());
    
    // Decrypt
    auto err = decrypt_aes(plaintext, nonce, tag);
    if (err) return std::unexpected(err);
    
    return std::string(
        reinterpret_cast<char*>(plaintext.data()),
        plaintext.size()
    );
}

result<PsyferContext::EncryptResult> PsyferContext::encrypt_chacha(
    std::span<std::byte> plaintext,
    std::span<const std::byte> aad
) noexcept {
    EncryptResult result;
    
    // Generate fresh nonce
    auto err = secure_random::generate(result.nonce);
    if (err) return std::unexpected(err);
    
    // Encrypt in place
    chacha20_poly1305 cipher;
    err = cipher.encrypt(plaintext, master_key_.span(), result.nonce, result.tag, aad);
    if (err) return std::unexpected(err);
    
    return result;
}

std::error_code PsyferContext::decrypt_chacha(
    std::span<std::byte> ciphertext,
    std::span<const std::byte, 12> nonce,
    std::span<const std::byte, 16> tag,
    std::span<const std::byte> aad
) noexcept {
    chacha20_poly1305 cipher;
    return cipher.decrypt(ciphertext, master_key_.span(), nonce, tag, aad);
}

// ===== Asymmetric Encryption Implementation =====

result<std::vector<std::byte>> PsyferContext::encrypt_for(
    std::span<const std::byte> plaintext,
    std::span<const std::byte, 32> recipient_public_key
) noexcept {
    // Compute shared secret
    std::array<std::byte, 32> shared_secret;
    auto err = x25519_keypair_.compute_shared_secret(recipient_public_key, shared_secret);
    if (err) return std::unexpected(err);
    
    // Derive encryption key from shared secret
    std::array<std::byte, 32> enc_key;
    err = hkdf::derive_sha256(
        shared_secret,
        x25519_keypair_.public_key,  // Use our public key as salt
        std::as_bytes(std::span("psyfer-x25519-encrypt")),
        enc_key
    );
    if (err) return std::unexpected(err);
    
    // Encrypt using derived key
    auto encrypted = quick_encrypt(plaintext, enc_key);
    if (!encrypted) return encrypted;
    
    // Prepend our public key so recipient knows who sent it
    std::vector<std::byte> result(32 + encrypted->size());
    std::memcpy(result.data(), x25519_keypair_.public_key.data(), 32);
    std::memcpy(result.data() + 32, encrypted->data(), encrypted->size());
    
    return result;
}

result<std::vector<std::byte>> PsyferContext::decrypt_from(
    std::span<const std::byte> ciphertext,
    std::span<const std::byte, 32> sender_public_key
) noexcept {
    if (ciphertext.size() < 32 + 28) {  // Public key + nonce + tag minimum
        return std::unexpected(make_error_code(error_code::invalid_buffer_size));
    }
    
    // Skip sender's public key (first 32 bytes) if included
    std::span<const std::byte> encrypted_data = ciphertext;
    if (ciphertext.size() > 60) {  // Likely includes public key
        encrypted_data = ciphertext.subspan(32);
    }
    
    // Compute shared secret
    std::array<std::byte, 32> shared_secret;
    auto err = x25519_keypair_.compute_shared_secret(sender_public_key, shared_secret);
    if (err) return std::unexpected(err);
    
    // Derive decryption key
    std::array<std::byte, 32> dec_key;
    err = hkdf::derive_sha256(
        shared_secret,
        sender_public_key,  // Use sender's public key as salt
        std::as_bytes(std::span("psyfer-x25519-encrypt")),
        dec_key
    );
    if (err) return std::unexpected(err);
    
    // Decrypt using derived key
    return quick_decrypt(encrypted_data, dec_key);
}

// ===== Digital Signatures Implementation =====

result<std::array<std::byte, 64>> PsyferContext::sign(
    std::span<const std::byte> message
) noexcept {
    std::array<std::byte, 64> signature;
    auto err = ed25519::sign(message, ed25519_keypair_.private_key, signature);
    if (err) return std::unexpected(err);
    return signature;
}

result<std::array<std::byte, 64>> PsyferContext::sign_string(
    std::string_view message
) noexcept {
    return sign(std::as_bytes(std::span(message)));
}

bool PsyferContext::verify(
    std::span<const std::byte> message,
    std::span<const std::byte, 64> signature,
    std::span<const std::byte, 32> public_key
) noexcept {
    return ed25519::verify(message, signature, public_key);
}

// ===== Message Authentication Implementation =====

std::array<std::byte, 32> PsyferContext::hmac256(
    std::span<const std::byte> message
) noexcept {
    std::array<std::byte, 32> mac;
    hmac_sha256_algorithm::hmac(hmac_key_.span(), message, mac);
    return mac;
}

std::array<std::byte, 64> PsyferContext::hmac512(
    std::span<const std::byte> message
) noexcept {
    std::array<std::byte, 64> mac;
    hmac_sha512_algorithm::hmac(hmac_key_.span(), message, mac);
    return mac;
}

bool PsyferContext::verify_hmac256(
    std::span<const std::byte> message,
    std::span<const std::byte, 32> mac
) noexcept {
    auto computed = hmac256(message);
    return secure_compare(computed.data(), mac.data(), 32);
}

// ===== Key Derivation Implementation =====

result<secure_key_256> PsyferContext::derive_key(
    std::string_view purpose,
    std::span<const std::byte> salt
) noexcept {
    std::array<std::byte, 32> derived;
    auto err = hkdf::derive_sha256(
        master_key_.span(),
        salt,
        std::as_bytes(std::span(purpose)),
        derived
    );
    if (err) return std::unexpected(err);
    
    return secure_key_256::from_bytes(derived);
}

template<size_t KeySize>
result<secure_key<KeySize>> PsyferContext::derive_key_sized(
    std::string_view purpose,
    std::span<const std::byte> salt
) noexcept {
    std::array<std::byte, KeySize> derived;
    
    // Use appropriate KDF based on size
    std::error_code err;
    if (KeySize <= 32) {
        std::array<std::byte, 32> temp;
        err = hkdf::derive_sha256(
            master_key_.span(),
            salt,
            std::as_bytes(std::span(purpose)),
            temp
        );
        if (!err) {
            std::memcpy(derived.data(), temp.data(), KeySize);
        }
    } else {
        err = hkdf::derive_sha512(
            master_key_.span(),
            salt,
            std::as_bytes(std::span(purpose)),
            derived
        );
    }
    
    if (err) return std::unexpected(err);
    
    return secure_key<KeySize>::from_bytes(derived);
}

// Explicit instantiations for common key sizes
template result<secure_key<16>> PsyferContext::derive_key_sized<16>(
    std::string_view, std::span<const std::byte>) noexcept;
template result<secure_key<32>> PsyferContext::derive_key_sized<32>(
    std::string_view, std::span<const std::byte>) noexcept;
template result<secure_key<64>> PsyferContext::derive_key_sized<64>(
    std::string_view, std::span<const std::byte>) noexcept;

// ===== Key Management Implementation =====

bool PsyferContext::needs_rotation() const noexcept {
    auto age = std::chrono::system_clock::now() - created_at_;
    return age > rotation_period_;
}

std::error_code PsyferContext::rotate_keys() noexcept {
    // Generate new master key
    auto key_result = secure_key_256::generate();
    if (!key_result) return key_result.error();
    
    // Clear old keys
    master_key_.clear();
    hmac_key_.clear();
    psy_key_.clear();
    
    // Set new master key
    master_key_ = std::move(key_result.value());
    created_at_ = std::chrono::system_clock::now();
    
    // Derive new subkeys
    return derive_subkeys();
}

// ===== Persistence Implementation =====

result<std::unique_ptr<PsyferContext>> PsyferContext::load(
    std::span<const std::byte> encrypted_data,
    std::span<const std::byte, 32> master_key
) noexcept {
    // Decrypt the data
    auto decrypted = quick_decrypt(encrypted_data, master_key);
    if (!decrypted) return std::unexpected(decrypted.error());
    
    // Parse the decrypted data
    BufferReader reader(*decrypted);
    
    // Read version
    auto version = reader.read_u32();
    if (!version || *version != 1) {
        return std::unexpected(make_error_code(error_code::invalid_argument));
    }
    
    auto ctx = std::unique_ptr<PsyferContext>(new PsyferContext());
    
    // Read identity
    auto identity = reader.read_string_field();
    if (identity) ctx->identity_name_ = std::string(*identity);
    
    // Read creation time
    auto created = reader.read_u64();
    if (created) {
        ctx->created_at_ = std::chrono::system_clock::time_point(
            std::chrono::seconds(*created)
        );
    }
    
    // Read rotation period
    auto rotation = reader.read_u64();
    if (rotation) {
        ctx->rotation_period_ = std::chrono::hours(*rotation);
    }
    
    // Read keys
    auto master_key_data = reader.read_bytes_field();
    if (master_key_data && master_key_data->size() == 32) {
        std::array<std::byte, 32> key_array;
        std::memcpy(key_array.data(), master_key_data->data(), 32);
        ctx->master_key_ = secure_key_256::from_bytes(key_array);
    }
    
    // Read X25519 keypair
    auto x25519_private = reader.read_bytes_field();
    if (x25519_private && x25519_private->size() == 32) {
        std::memcpy(ctx->x25519_keypair_.private_key.data(), 
                   x25519_private->data(), 32);
        [[maybe_unused]] auto err = x25519::derive_public_key(
            ctx->x25519_keypair_.private_key,
            ctx->x25519_keypair_.public_key
        );
    }
    
    // Read Ed25519 keypair
    auto ed25519_private = reader.read_bytes_field();
    if (ed25519_private && ed25519_private->size() == 32) {
        std::memcpy(ctx->ed25519_keypair_.private_key.data(), 
                   ed25519_private->data(), 32);
        ed25519::public_key_from_private(
            ctx->ed25519_keypair_.private_key,
            ctx->ed25519_keypair_.public_key
        );
    }
    
    // Derive subkeys
    auto err = ctx->derive_subkeys();
    if (err) return std::unexpected(err);
    
    return ctx;
}

result<std::vector<std::byte>> PsyferContext::save(
    std::span<const std::byte, 32> master_key
) const noexcept {
    // Serialize context
    std::vector<std::byte> buffer;
    buffer.reserve(512);  // Estimate
    
    BufferWriter writer(buffer);
    
    // Write version
    writer.write_u32(1);
    
    // Write identity
    writer.write_field_header(1, WireType::BYTES);
    writer.write_string_field(identity_name_);
    
    // Write creation time
    writer.write_field_header(2, WireType::FIXED64);
    writer.write_u64(std::chrono::duration_cast<std::chrono::seconds>(
        created_at_.time_since_epoch()).count());
    
    // Write rotation period
    writer.write_field_header(3, WireType::FIXED64);
    writer.write_u64(rotation_period_.count());
    
    // Write master key
    writer.write_field_header(4, WireType::BYTES);
    writer.write_bytes_field(master_key_.span());
    
    // Write X25519 private key
    writer.write_field_header(5, WireType::BYTES);
    writer.write_bytes_field(x25519_keypair_.private_key);
    
    // Write Ed25519 private key
    writer.write_field_header(6, WireType::BYTES);
    writer.write_bytes_field(ed25519_keypair_.private_key);
    
    buffer.resize(writer.position());
    
    // Encrypt the serialized data
    return quick_encrypt(buffer, master_key);
}

// Destructor - secure cleanup
PsyferContext::~PsyferContext() noexcept {
    // Keys are automatically cleared by secure_key destructors
    // Clear sensitive metadata
    identity_name_.clear();
}

} // namespace psyfer