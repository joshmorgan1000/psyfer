/**
 * @file generated_impl.cpp
 * @brief Implementation for psy-c generated code
 * @warning This file is auto-generated. Do not edit manually.
 */

#include "basic.hpp"
#include <psyfer.hpp>

namespace test {

size_t SimpleMessage::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + varint_size(id);
    size += field_header_size(2) + string_field_size(content);
    return size;
}

size_t SimpleMessage::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::VARINT);
    writer.write_varint(id);
    
    writer.write_field_header(2, WireType::BYTES);
    writer.write_string_field(content);
    
    return writer.position();
}

std::vector<std::byte> SimpleMessage::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<SimpleMessage> SimpleMessage::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    SimpleMessage result;
    
    // Field 1: id
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.id = static_cast<uint64_t>(*val);
    }
    
    // Field 2: content
    auto header2 = reader.read_field_header();
    if (!header2 || header2->field_number != 2) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.content = *val;
    }
    
    return result;
}

size_t SimpleMessage::deserialize(
    std::span<const std::byte> source_buffer,
    SimpleMessage* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

size_t SecureData::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + bytes_field_size(data.size());
    return size;
}

size_t SecureData::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::BYTES);
    writer.write_bytes_field(data);
    
    return writer.position();
}

std::vector<std::byte> SecureData::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<SecureData> SecureData::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    SecureData result;
    
    // Field 1: data
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_bytes_field();
        if (!val) return std::nullopt;
        result.data.assign(val->begin(), val->end());
    }
    
    return result;
}

size_t SecureData::deserialize(
    std::span<const std::byte> source_buffer,
    SecureData* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

// Encryption implementation
size_t SecureData::encrypted_size() const noexcept {
    // AES-256-GCM: serialized + nonce(12) + tag(16)
    return serialized_size() + 12 + 16;
}

size_t SecureData::encrypt(
    std::span<std::byte> buffer,
    std::span<const std::byte> key
) const noexcept {
    // Layout: [nonce:12][encrypted_data][tag:16]
    
    // Generate nonce
    auto nonce = buffer.subspan(0, 12);
    psyfer::utils::secure_random::generate(nonce);
    
    // Serialize to position after nonce
    auto data_start = buffer.subspan(12);
    size_t serialized_size = serialize(data_start);
    
    // Encrypt in-place
    auto tag = buffer.subspan(12 + serialized_size, 16);
    auto result = psyfer::crypto::aes256_gcm::encrypt_oneshot(
        data_start.subspan(0, serialized_size),
        std::span<const std::byte, 32>(key.data(), 32),
        std::span<const std::byte, 12>(nonce.data(), 12),
        std::span<std::byte, 16>(tag.data(), 16),
        {}  // no AAD
    );
    
    if (result != psyfer::error_code::success) {
        return 0;
    }
    
    return 12 + serialized_size + 16;
}

std::optional<SecureData> SecureData::decrypt(
    std::span<const std::byte> buffer,
    std::span<const std::byte> key
) noexcept {
    if (buffer.size() < 28) return std::nullopt;  // min size
    
    // Extract components
    auto nonce = buffer.subspan(0, 12);
    auto tag = buffer.subspan(buffer.size() - 16, 16);
    auto encrypted = buffer.subspan(12, buffer.size() - 28);
    
    // Decrypt to temporary buffer
    std::vector<std::byte> decrypted(encrypted.size());
    std::memcpy(decrypted.data(), encrypted.data(), encrypted.size());
    
    auto result = psyfer::crypto::aes256_gcm::decrypt_oneshot(
        decrypted,
        std::span<const std::byte, 32>(key.data(), 32),
        std::span<const std::byte, 12>(nonce.data(), 12),
        std::span<const std::byte, 16>(tag.data(), 16),
        {}  // no AAD
    );
    
    if (result != psyfer::error_code::success) {
        return std::nullopt;
    }
    
    // Deserialize decrypted data
    return deserialize(decrypted);
}

size_t SecureDoc::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + string_field_size(content);
    return size;
}

size_t SecureDoc::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::BYTES);
    writer.write_string_field(content);
    
    return writer.position();
}

std::vector<std::byte> SecureDoc::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<SecureDoc> SecureDoc::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    SecureDoc result;
    
    // Field 1: content
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.content = *val;
    }
    
    return result;
}

size_t SecureDoc::deserialize(
    std::span<const std::byte> source_buffer,
    SecureDoc* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

// Encryption implementation
size_t SecureDoc::encrypted_size() const noexcept {
    // ChaCha20-Poly1305: serialized + nonce(12) + tag(16)
    return serialized_size() + 12 + 16;
}

size_t SecureDoc::encrypt(
    std::span<std::byte> buffer,
    std::span<const std::byte> key
) const noexcept {
    // Layout: [nonce:12][encrypted_data][tag:16]
    
    // Generate nonce
    auto nonce = buffer.subspan(0, 12);
    psyfer::utils::secure_random::generate(nonce);
    
    // Serialize to position after nonce
    auto data_start = buffer.subspan(12);
    size_t serialized_size = serialize(data_start);
    
    // Encrypt in-place
    auto tag = buffer.subspan(12 + serialized_size, 16);
    auto result = psyfer::crypto::chacha20_poly1305::encrypt_oneshot(
        data_start.subspan(0, serialized_size),
        std::span<const std::byte, 32>(key.data(), 32),
        std::span<const std::byte, 12>(nonce.data(), 12),
        std::span<std::byte, 16>(tag.data(), 16),
        {}  // no AAD
    );
    
    if (result != psyfer::error_code::success) {
        return 0;
    }
    
    return 12 + serialized_size + 16;
}

std::optional<SecureDoc> SecureDoc::decrypt(
    std::span<const std::byte> buffer,
    std::span<const std::byte> key
) noexcept {
    if (buffer.size() < 28) return std::nullopt;  // min size
    
    // Extract components
    auto nonce = buffer.subspan(0, 12);
    auto tag = buffer.subspan(buffer.size() - 16, 16);
    auto encrypted = buffer.subspan(12, buffer.size() - 28);
    
    // Decrypt to temporary buffer
    std::vector<std::byte> decrypted(encrypted.size());
    std::memcpy(decrypted.data(), encrypted.data(), encrypted.size());
    
    auto result = psyfer::crypto::chacha20_poly1305::decrypt_oneshot(
        decrypted,
        std::span<const std::byte, 32>(key.data(), 32),
        std::span<const std::byte, 12>(nonce.data(), 12),
        std::span<const std::byte, 16>(tag.data(), 16),
        {}  // no AAD
    );
    
    if (result != psyfer::error_code::success) {
        return std::nullopt;
    }
    
    // Deserialize decrypted data
    return deserialize(decrypted);
}

} // namespace test
