/**
 * @file example_impl.cpp
 * @brief Example implementation showing how generated code uses the runtime
 */

#include <psyfer.hpp>
#include <cstring>

namespace example::crypto {

using namespace psyfer::serialization;

// Example implementation for SecureMessage
size_t SecureMessage::serialized_size() const noexcept {
    size_t size = 0;
    
    // Field 1: id (uint64)
    size += field_header_size(1) + 8;
    
    // Field 2: timestamp (int64)
    size += field_header_size(2) + 8;
    
    // Field 3: content (bytes)
    size += field_header_size(3) + bytes_field_size(content.size());
    
    // Field 4: secret_key (bytes)
    size += field_header_size(4) + bytes_field_size(secret_key.size());
    
    // Field 5: metadata (optional string)
    if (metadata.has_value()) {
        size += field_header_size(5) + string_field_size(*metadata);
    }
    
    return size;
}

size_t SecureMessage::serialize(std::span<std::byte> buffer) const noexcept {
    BufferWriter writer(buffer);
    
    // Field 1: id
    writer.write_field_header(1, WireType::FIXED64);
    writer.write_u64(id);
    
    // Field 2: timestamp
    writer.write_field_header(2, WireType::FIXED64);
    writer.write_u64(static_cast<uint64_t>(timestamp));
    
    // Field 3: content (encrypted with aes256)
    writer.write_field_header(3, WireType::BYTES);
    writer.write_bytes_field(content);
    
    // Field 4: secret_key (encrypted with chacha20)
    writer.write_field_header(4, WireType::BYTES);
    writer.write_bytes_field(secret_key);
    
    // Field 5: metadata (optional)
    if (metadata.has_value()) {
        writer.write_field_header(5, WireType::BYTES);
        writer.write_string_field(*metadata);
    }
    
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
    BufferReader reader(buffer);
    SecureMessage msg;
    
    while (reader.remaining() > 0) {
        auto header = reader.read_field_header();
        if (!header) break;
        
        switch (header->field_number) {
        case 1: // id
            if (auto val = reader.read_u64()) {
                msg.id = *val;
            }
            break;
            
        case 2: // timestamp
            if (auto val = reader.read_u64()) {
                msg.timestamp = static_cast<int64_t>(*val);
            }
            break;
            
        case 3: // content
            if (auto data = reader.read_bytes_field()) {
                msg.content.assign(data->begin(), data->end());
            }
            break;
            
        case 4: // secret_key
            if (auto data = reader.read_bytes_field()) {
                msg.secret_key.assign(data->begin(), data->end());
            }
            break;
            
        case 5: // metadata
            if (auto str = reader.read_string_field()) {
                msg.metadata = std::string(*str);
            }
            break;
            
        default:
            // Skip unknown fields
            switch (header->wire_type) {
            case WireType::VARINT:
                reader.read_varint();
                break;
            case WireType::FIXED64:
                reader.skip(8);
                break;
            case WireType::FIXED32:
                reader.skip(4);
                break;
            case WireType::BYTES:
                if (auto len = reader.read_varint()) {
                    reader.skip(*len);
                }
                break;
            }
        }
    }
    
    return msg;
}

size_t SecureMessage::deserialize(
    std::span<const std::byte> source_buffer,
    SecureMessage* target
) noexcept {
    if (!target) return 0;
    
    BufferReader reader(source_buffer);
    
    while (reader.remaining() > 0) {
        auto header = reader.read_field_header();
        if (!header) break;
        
        switch (header->field_number) {
        case 1: // id
            if (auto val = reader.read_u64()) {
                target->id = *val;
            }
            break;
            
        case 2: // timestamp
            if (auto val = reader.read_u64()) {
                target->timestamp = static_cast<int64_t>(*val);
            }
            break;
            
        case 3: // content
            if (auto data = reader.read_bytes_field()) {
                target->content.assign(data->begin(), data->end());
            }
            break;
            
        case 4: // secret_key
            if (auto data = reader.read_bytes_field()) {
                target->secret_key.assign(data->begin(), data->end());
            }
            break;
            
        case 5: // metadata
            if (auto str = reader.read_string_field()) {
                target->metadata = std::string(*str);
            }
            break;
            
        default:
            // Skip unknown fields
            switch (header->wire_type) {
            case WireType::VARINT:
                reader.read_varint();
                break;
            case WireType::FIXED64:
                reader.skip(8);
                break;
            case WireType::FIXED32:
                reader.skip(4);
                break;
            case WireType::BYTES:
                if (auto len = reader.read_varint()) {
                    reader.skip(*len);
                }
                break;
            }
        }
    }
    
    return reader.position();
}

// Encryption methods
size_t SecureMessage::encrypted_size() const noexcept {
    // For now, assume encryption adds 16 bytes for tag + 12 bytes for nonce
    return serialized_size() + 28;
}

size_t SecureMessage::encrypt(
    std::span<std::byte> buffer,
    std::span<const std::byte> key
) const noexcept {
    // First serialize
    size_t serialized = serialize(buffer);
    
    // Then encrypt in-place
    // This is where we'd use psyfer's encryption algorithms
    // For now, just return the serialized size
    return serialized;
}

std::vector<std::byte> SecureMessage::encrypt(
    std::span<const std::byte> key
) const {
    std::vector<std::byte> buffer(encrypted_size());
    encrypt(buffer, key);
    return buffer;
}

std::optional<SecureMessage> SecureMessage::decrypt(
    std::span<const std::byte> buffer,
    std::span<const std::byte> key
) noexcept {
    // First decrypt to temporary buffer
    // Then deserialize
    return deserialize(buffer);
}

size_t SecureMessage::decrypt(
    std::span<const std::byte> source_buffer,
    SecureMessage* target,
    std::span<const std::byte> key
) noexcept {
    // Decrypt and deserialize directly into target
    // This avoids intermediate allocations
    return deserialize(source_buffer, target);
}

} // namespace example::crypto