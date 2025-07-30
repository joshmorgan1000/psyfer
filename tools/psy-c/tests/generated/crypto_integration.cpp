/**
 * @file generated_impl.cpp
 * @brief Implementation for psy-c generated code
 * @warning This file is auto-generated. Do not edit manually.
 */

#include "crypto_integration.hpp"
#include <psyfer.hpp>

namespace crypto_integration_test {

size_t SecureMessage::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + varint_size(message_id);
    size += field_header_size(2) + string_field_size(sender);
    size += field_header_size(3) + string_field_size(content);
    size += field_header_size(4) + varint_size(timestamp);
    return size;
}

size_t SecureMessage::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::VARINT);
    writer.write_varint(message_id);
    
    writer.write_field_header(2, WireType::BYTES);
    writer.write_string_field(sender);
    
    writer.write_field_header(3, WireType::BYTES);
    writer.write_string_field(content);
    
    writer.write_field_header(4, WireType::VARINT);
    writer.write_varint(timestamp);
    
    return writer.position();
}

std::vector<std::byte> SecureMessage::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<SecureMessage> SecureMessage::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    SecureMessage result;
    
    // Field 1: message_id
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.message_id = static_cast<uint64_t>(*val);
    }
    
    // Field 2: sender
    auto header2 = reader.read_field_header();
    if (!header2 || header2->field_number != 2) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.sender = *val;
    }
    
    // Field 3: content
    auto header3 = reader.read_field_header();
    if (!header3 || header3->field_number != 3) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.content = *val;
    }
    
    // Field 4: timestamp
    auto header4 = reader.read_field_header();
    if (!header4 || header4->field_number != 4) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.timestamp = static_cast<uint64_t>(*val);
    }
    
    return result;
}

size_t SecureMessage::deserialize(
    std::span<const std::byte> source_buffer,
    SecureMessage* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

// Encryption implementation
size_t SecureMessage::encrypted_size() const noexcept {
    // AES-256-GCM: serialized + nonce(12) + tag(16)
    return serialized_size() + 12 + 16;
}

size_t SecureMessage::encrypt(
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

std::optional<SecureMessage> SecureMessage::decrypt(
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

size_t SecureDocument::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + string_field_size(doc_id);
    size += field_header_size(2) + string_field_size(title);
    size += field_header_size(3) + bytes_field_size(body.size());
    size += field_header_size(4) + varint_size(version);
    return size;
}

size_t SecureDocument::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::BYTES);
    writer.write_string_field(doc_id);
    
    writer.write_field_header(2, WireType::BYTES);
    writer.write_string_field(title);
    
    writer.write_field_header(3, WireType::BYTES);
    writer.write_bytes_field(body);
    
    writer.write_field_header(4, WireType::VARINT);
    writer.write_varint(version);
    
    return writer.position();
}

std::vector<std::byte> SecureDocument::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<SecureDocument> SecureDocument::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    SecureDocument result;
    
    // Field 1: doc_id
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.doc_id = *val;
    }
    
    // Field 2: title
    auto header2 = reader.read_field_header();
    if (!header2 || header2->field_number != 2) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.title = *val;
    }
    
    // Field 3: body
    auto header3 = reader.read_field_header();
    if (!header3 || header3->field_number != 3) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_bytes_field();
        if (!val) return std::nullopt;
        result.body.assign(val->begin(), val->end());
    }
    
    // Field 4: version
    auto header4 = reader.read_field_header();
    if (!header4 || header4->field_number != 4) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.version = static_cast<uint32_t>(*val);
    }
    
    return result;
}

size_t SecureDocument::deserialize(
    std::span<const std::byte> source_buffer,
    SecureDocument* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

// Encryption implementation
size_t SecureDocument::encrypted_size() const noexcept {
    // ChaCha20-Poly1305: serialized + nonce(12) + tag(16)
    return serialized_size() + 12 + 16;
}

size_t SecureDocument::encrypt(
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

std::optional<SecureDocument> SecureDocument::decrypt(
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

// Compression implementation
size_t SecureDocument::compressed_size() const noexcept {
    // LZ4: worst case is slightly larger than input
    size_t input_size = serialized_size();
    return input_size + (input_size/255) + 16;
}

size_t SecureDocument::compress(
    std::span<std::byte> buffer
) const noexcept {
    // Serialize first
    std::vector<std::byte> serialized(serialized_size());
    size_t serialized_len = serialize(serialized);
    
    // Compress with LZ4
    psyfer::compression::lz4 compressor;
    auto result = compressor.compress(
        std::span(serialized.data(), serialized_len),
        buffer
    );
    return result ? *result : 0;
}

std::vector<std::byte> SecureDocument::compress() const {
    std::vector<std::byte> result(compressed_size());
    size_t compressed_len = compress(result);
    result.resize(compressed_len);
    return result;
}

std::optional<SecureDocument> SecureDocument::decompress(
    std::span<const std::byte> buffer
) noexcept {
    // Allocate decompression buffer
    std::vector<std::byte> decompressed;
    
    // Decompress with LZ4
    // First, try to determine uncompressed size
    psyfer::compression::lz4 decompressor;
    // Allocate a reasonable buffer (assume 10x expansion)
    decompressed.resize(buffer.size() * 10);
    auto result = decompressor.decompress(buffer, decompressed);
    if (!result) return std::nullopt;
    decompressed.resize(*result);
    
    // Deserialize decompressed data
    return deserialize(decompressed);
}

size_t SecureDocument::decompress(
    std::span<const std::byte> source_buffer,
    SecureDocument* target
) noexcept {
    auto result = decompress(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return 1;  // Success
}

size_t UserData::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + varint_size(user_id);
    size += field_header_size(2) + string_field_size(api_key);
    size += field_header_size(3) + string_field_size(private_notes);
    size += field_header_size(4) + string_field_size(password);
    size += field_header_size(5) + bytes_field_size(avatar.size());
    return size;
}

size_t UserData::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::VARINT);
    writer.write_varint(user_id);
    
    writer.write_field_header(2, WireType::BYTES);
    writer.write_string_field(api_key);
    
    writer.write_field_header(3, WireType::BYTES);
    writer.write_string_field(private_notes);
    
    writer.write_field_header(4, WireType::BYTES);
    writer.write_string_field(password);
    
    writer.write_field_header(5, WireType::BYTES);
    writer.write_bytes_field(avatar);
    
    
    return writer.position();
}

std::vector<std::byte> UserData::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<UserData> UserData::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    UserData result;
    
    // Field 1: user_id
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.user_id = static_cast<uint64_t>(*val);
    }
    
    // Field 2: api_key
    auto header2 = reader.read_field_header();
    if (!header2 || header2->field_number != 2) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.api_key = *val;
    }
    
    // Field 3: private_notes
    auto header3 = reader.read_field_header();
    if (!header3 || header3->field_number != 3) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.private_notes = *val;
    }
    
    // Field 4: password
    auto header4 = reader.read_field_header();
    if (!header4 || header4->field_number != 4) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_string_field();
        if (!val) return std::nullopt;
        result.password = *val;
    }
    
    // Field 5: avatar
    auto header5 = reader.read_field_header();
    if (!header5 || header5->field_number != 5) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_bytes_field();
        if (!val) return std::nullopt;
        result.avatar.assign(val->begin(), val->end());
    }
    
    return result;
}

size_t UserData::deserialize(
    std::span<const std::byte> source_buffer,
    UserData* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

// Encryption implementation
size_t UserData::encrypted_size() const noexcept {
    // AES-256-GCM: serialized + nonce(12) + tag(16)
    return serialized_size() + 12 + 16;
}

size_t UserData::encrypt(
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

std::optional<UserData> UserData::decrypt(
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

// Compression implementation
size_t UserData::compressed_size() const noexcept {
    // LZ4: worst case is slightly larger than input
    size_t input_size = serialized_size();
    return input_size + (input_size/255) + 16;
}

size_t UserData::compress(
    std::span<std::byte> buffer
) const noexcept {
    // Serialize first
    std::vector<std::byte> serialized(serialized_size());
    size_t serialized_len = serialize(serialized);
    
    // Compress with LZ4
    psyfer::compression::lz4 compressor;
    auto result = compressor.compress(
        std::span(serialized.data(), serialized_len),
        buffer
    );
    return result ? *result : 0;
}

std::vector<std::byte> UserData::compress() const {
    std::vector<std::byte> result(compressed_size());
    size_t compressed_len = compress(result);
    result.resize(compressed_len);
    return result;
}

std::optional<UserData> UserData::decompress(
    std::span<const std::byte> buffer
) noexcept {
    // Allocate decompression buffer
    std::vector<std::byte> decompressed;
    
    // Decompress with LZ4
    // First, try to determine uncompressed size
    psyfer::compression::lz4 decompressor;
    // Allocate a reasonable buffer (assume 10x expansion)
    decompressed.resize(buffer.size() * 10);
    auto result = decompressor.decompress(buffer, decompressed);
    if (!result) return std::nullopt;
    decompressed.resize(*result);
    
    // Deserialize decompressed data
    return deserialize(decompressed);
}

size_t UserData::decompress(
    std::span<const std::byte> source_buffer,
    UserData* target
) noexcept {
    auto result = decompress(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return 1;  // Success
}

size_t AuthenticatedData::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + varint_size(sequence);
    size += field_header_size(2) + bytes_field_size(data.size());
    size += field_header_size(3) + varint_size(timestamp);
    return size;
}

size_t AuthenticatedData::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::VARINT);
    writer.write_varint(sequence);
    
    writer.write_field_header(2, WireType::BYTES);
    writer.write_bytes_field(data);
    
    writer.write_field_header(3, WireType::VARINT);
    writer.write_varint(timestamp);
    
    return writer.position();
}

std::vector<std::byte> AuthenticatedData::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<AuthenticatedData> AuthenticatedData::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    AuthenticatedData result;
    
    // Field 1: sequence
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.sequence = static_cast<uint64_t>(*val);
    }
    
    // Field 2: data
    auto header2 = reader.read_field_header();
    if (!header2 || header2->field_number != 2) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_bytes_field();
        if (!val) return std::nullopt;
        result.data.assign(val->begin(), val->end());
    }
    
    // Field 3: timestamp
    auto header3 = reader.read_field_header();
    if (!header3 || header3->field_number != 3) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.timestamp = static_cast<uint64_t>(*val);
    }
    
    return result;
}

size_t AuthenticatedData::deserialize(
    std::span<const std::byte> source_buffer,
    AuthenticatedData* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

size_t IntegrityProtectedConfig::serialized_size() const noexcept {
    using namespace psyfer::serialization;
    size_t size = 0;
    
    size += field_header_size(1) + varint_size(version);
    size += field_header_size(3) + varint_size(last_modified);
    return size;
}

size_t IntegrityProtectedConfig::serialize(std::span<std::byte> buffer) const noexcept {
    using namespace psyfer::serialization;
    BufferWriter writer(buffer);
    
    writer.write_field_header(1, WireType::VARINT);
    writer.write_varint(version);
    
    
    writer.write_field_header(3, WireType::VARINT);
    writer.write_varint(last_modified);
    
    return writer.position();
}

std::vector<std::byte> IntegrityProtectedConfig::serialize() const {
    std::vector<std::byte> buffer(serialized_size());
    serialize(buffer);
    return buffer;
}

std::optional<IntegrityProtectedConfig> IntegrityProtectedConfig::deserialize(
    std::span<const std::byte> buffer
) noexcept {
    using namespace psyfer::serialization;
    BufferReader reader(buffer);
    IntegrityProtectedConfig result;
    
    // Field 1: version
    auto header1 = reader.read_field_header();
    if (!header1 || header1->field_number != 1) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.version = static_cast<uint32_t>(*val);
    }
    
    // Field 3: last_modified
    auto header3 = reader.read_field_header();
    if (!header3 || header3->field_number != 3) {
        return std::nullopt; // Required field missing
    } else {
        auto val = reader.read_varint();
        if (!val) return std::nullopt;
        result.last_modified = static_cast<uint64_t>(*val);
    }
    
    return result;
}

size_t IntegrityProtectedConfig::deserialize(
    std::span<const std::byte> source_buffer,
    IntegrityProtectedConfig* target
) noexcept {
    auto result = deserialize(source_buffer);
    if (!result) return 0;
    *target = std::move(*result);
    return source_buffer.size();
}

} // namespace crypto_integration_test
