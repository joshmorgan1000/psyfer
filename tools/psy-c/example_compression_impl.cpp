/**
 * @file example_compression_impl.cpp
 * @brief Example implementation showing compression integration
 */

#include <psyfer.hpp>
#include <psyfer/serialization/psy_runtime.hpp>
#include <psyfer/compression/lz4.hpp>
#include <psyfer/compression/fpc.hpp>

namespace example::crypto {

using namespace psyfer::serialization;

// Example for SecureMessage with field-level compression
size_t SecureMessage::compressed_size() const noexcept {
    // First calculate serialized size
    size_t ser_size = serialized_size();
    
    // For fields with compression, we need to estimate compressed size
    // LZ4 worst case is original size + overhead
    return psyfer::compression::lz4::max_compressed_size(ser_size);
}

size_t SecureMessage::compress(std::span<std::byte> buffer) const noexcept {
    // Strategy for field-level compression:
    // 1. Serialize the message
    // 2. For each compressed field, compress it individually
    // 3. Re-encode with compressed data
    
    // For now, let's do a simple approach - compress the whole message
    std::vector<std::byte> serialized(serialized_size());
    size_t ser_size = serialize(serialized);
    
    // Compress using LZ4
    psyfer::compression::lz4 compressor;
    auto result = compressor.compress(
        std::span(serialized.data(), ser_size),
        buffer
    );
    
    return result.value_or(0);
}

std::vector<std::byte> SecureMessage::compress() const {
    std::vector<std::byte> buffer(compressed_size());
    size_t actual_size = compress(buffer);
    buffer.resize(actual_size);
    return buffer;
}

std::optional<SecureMessage> SecureMessage::decompress(
    std::span<const std::byte> buffer
) noexcept {
    // Decompress first
    psyfer::compression::lz4 decompressor;
    
    // Need to allocate a buffer for decompressed data
    // In real implementation, we'd have metadata about original size
    std::vector<std::byte> decompressed(buffer.size() * 10); // Estimate
    
    auto result = decompressor.decompress(buffer, decompressed);
    if (!result) return std::nullopt;
    
    // Then deserialize
    return deserialize(std::span(decompressed.data(), *result));
}

size_t SecureMessage::decompress(
    std::span<const std::byte> source_buffer,
    SecureMessage* target
) noexcept {
    if (!target) return 0;
    
    // For zero-copy, we'd need a temporary buffer for decompression
    // This is a limitation of compression - it's not truly zero-copy
    std::vector<std::byte> temp(source_buffer.size() * 10);
    
    psyfer::compression::lz4 decompressor;
    auto result = decompressor.decompress(source_buffer, temp);
    if (!result) return 0;
    
    return deserialize(std::span(temp.data(), *result), target);
}

// Example for EncryptedRecord with struct-level compression using FPC
size_t EncryptedRecord::compressed_size() const noexcept {
    // FPC is designed for floating-point data, but can handle general data
    size_t ser_size = serialized_size();
    
    // FPC compression ratio varies, but let's be conservative
    return ser_size + 1024; // Add some overhead
}

size_t EncryptedRecord::compress(std::span<std::byte> buffer) const noexcept {
    // First serialize
    std::vector<std::byte> serialized(serialized_size());
    size_t ser_size = serialize(serialized);
    
    // Then compress with FPC
    // Note: FPC is optimized for float64 arrays, so this is just for demo
    psyfer::compression::fpc::writer writer(buffer);
    
    // Convert bytes to doubles for FPC (not efficient, just for demo)
    size_t num_doubles = ser_size / sizeof(double);
    auto doubles = reinterpret_cast<const double*>(serialized.data());
    
    writer.write_header(num_doubles);
    writer.write_doubles(std::span(doubles, num_doubles));
    
    // Handle remaining bytes
    size_t remaining = ser_size % sizeof(double);
    if (remaining > 0) {
        // In real implementation, we'd handle this properly
    }
    
    return writer.bytes_written();
}

std::vector<std::byte> EncryptedRecord::compress() const {
    std::vector<std::byte> buffer(compressed_size());
    size_t actual_size = compress(buffer);
    buffer.resize(actual_size);
    return buffer;
}

std::optional<EncryptedRecord> EncryptedRecord::decompress(
    std::span<const std::byte> buffer
) noexcept {
    // Decompress with FPC
    psyfer::compression::fpc::reader reader(buffer);
    
    auto header = reader.read_header();
    if (!header) return std::nullopt;
    
    // Read doubles
    std::vector<double> doubles(header->num_values);
    if (!reader.read_doubles(doubles)) return std::nullopt;
    
    // Convert back to bytes
    auto bytes = std::as_bytes(std::span(doubles));
    
    // Deserialize
    return deserialize(bytes);
}

size_t EncryptedRecord::decompress(
    std::span<const std::byte> source_buffer,
    EncryptedRecord* target
) noexcept {
    if (!target) return 0;
    
    // Similar to above but with target
    psyfer::compression::fpc::reader reader(source_buffer);
    
    auto header = reader.read_header();
    if (!header) return 0;
    
    std::vector<double> doubles(header->num_values);
    if (!reader.read_doubles(doubles)) return 0;
    
    auto bytes = std::as_bytes(std::span(doubles));
    return deserialize(bytes, target);
}

} // namespace example::crypto