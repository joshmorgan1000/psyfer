/**
 * @file test_psy.cpp
 * @brief Test program for psy-c generated code
 */

#include <iostream>
#include <iomanip>
#include <chrono>

// Include the generated header (this would be the output of psy-c)
// For testing, we'll manually define the structures

#include <psyfer.hpp>
#include <psyfer/utils/secure_key.hpp>
#include <psyfer/serialization/psy_runtime.hpp>

namespace example::crypto {

struct SecureMessage {
    uint64_t id;
    int64_t timestamp;
    std::vector<std::byte> content;
    std::vector<std::byte> secret_key;
    std::optional<std::string> metadata;
    
    [[nodiscard]] size_t serialized_size() const noexcept;
    [[nodiscard]] size_t serialize(std::span<std::byte> buffer) const noexcept;
    [[nodiscard]] std::vector<std::byte> serialize() const;
    [[nodiscard]] static std::optional<SecureMessage> deserialize(std::span<const std::byte> buffer) noexcept;
    [[nodiscard]] static size_t deserialize(
        std::span<const std::byte> source_buffer,
        SecureMessage* target
    ) noexcept;
    
    [[nodiscard]] size_t encrypted_size() const noexcept;
    [[nodiscard]] size_t encrypt(
        std::span<std::byte> buffer,
        std::span<const std::byte> key
    ) const noexcept;
    [[nodiscard]] std::vector<std::byte> encrypt(
        std::span<const std::byte> key
    ) const;
    [[nodiscard]] static std::optional<SecureMessage> decrypt(
        std::span<const std::byte> buffer,
        std::span<const std::byte> key
    ) noexcept;
    [[nodiscard]] static size_t decrypt(
        std::span<const std::byte> source_buffer,
        SecureMessage* target,
        std::span<const std::byte> key
    ) noexcept;
};

} // namespace example::crypto

// Include implementation
#include "example_impl.cpp"

void print_bytes(std::span<const std::byte> data, const std::string& label) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), size_t(16)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 16) {
        std::cout << "...";
    }
    std::cout << std::dec << "\n";
}

int main() {
    using namespace example::crypto;
    
    std::cout << "=== Psy-C Serialization Test ===\n\n";
    
    // Create a test message
    SecureMessage msg;
    msg.id = 12345;
    msg.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Add some content
    std::string content_str = "Hello, Psyfer! This is encrypted content.";
    msg.content.resize(content_str.size());
    std::memcpy(msg.content.data(), content_str.data(), content_str.size());
    
    // Add a secret key
    msg.secret_key.resize(32);
    psyfer::utils::secure_random::generate(msg.secret_key);
    
    // Optional metadata
    msg.metadata = "Test message metadata";
    
    std::cout << "Original message:\n";
    std::cout << "  ID: " << msg.id << "\n";
    std::cout << "  Timestamp: " << msg.timestamp << "\n";
    std::cout << "  Content: " << content_str << "\n";
    std::cout << "  Metadata: " << msg.metadata.value_or("(none)") << "\n";
    print_bytes(msg.secret_key, "  Secret key");
    
    // Test serialization
    std::cout << "\n--- Serialization Test ---\n";
    size_t serialized_size = msg.serialized_size();
    std::cout << "Serialized size: " << serialized_size << " bytes\n";
    
    auto serialized = msg.serialize();
    print_bytes(serialized, "Serialized data");
    
    // Test deserialization
    std::cout << "\n--- Deserialization Test ---\n";
    auto deserialized = SecureMessage::deserialize(serialized);
    if (deserialized) {
        std::cout << "Deserialization successful!\n";
        std::cout << "  ID: " << deserialized->id << "\n";
        std::cout << "  Timestamp: " << deserialized->timestamp << "\n";
        std::string content(reinterpret_cast<const char*>(deserialized->content.data()),
                          deserialized->content.size());
        std::cout << "  Content: " << content << "\n";
        std::cout << "  Metadata: " << deserialized->metadata.value_or("(none)") << "\n";
        print_bytes(deserialized->secret_key, "  Secret key");
    } else {
        std::cout << "Deserialization failed!\n";
    }
    
    // Test zero-copy deserialization
    std::cout << "\n--- Zero-Copy Deserialization Test ---\n";
    SecureMessage target;
    size_t bytes_read = SecureMessage::deserialize(serialized, &target);
    std::cout << "Bytes read: " << bytes_read << "\n";
    std::cout << "  ID: " << target.id << "\n";
    std::cout << "  Timestamp: " << target.timestamp << "\n";
    
    // Test encryption (placeholder)
    std::cout << "\n--- Encryption Test ---\n";
    std::vector<std::byte> key_data(32);
    psyfer::utils::secure_random::generate(key_data);
    // Just use the key_data vector directly - no need for secure memory for this test
    
    size_t encrypted_size = msg.encrypted_size();
    std::cout << "Encrypted size: " << encrypted_size << " bytes\n";
    
    auto encrypted = msg.encrypt(key_data);
    print_bytes(encrypted, "Encrypted data");
    
    // Test combined decrypt + deserialize
    std::cout << "\n--- Zero-Copy Decrypt + Deserialize Test ---\n";
    SecureMessage decrypted_target;
    size_t decrypt_bytes = SecureMessage::decrypt(encrypted, &decrypted_target, key_data);
    std::cout << "Bytes processed: " << decrypt_bytes << "\n";
    std::cout << "  ID: " << decrypted_target.id << "\n";
    
    // Performance test
    std::cout << "\n--- Performance Test ---\n";
    const int iterations = 100000;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto ser = msg.serialize();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Serialization performance:\n";
    std::cout << "  " << iterations << " iterations in " << duration.count() << " µs\n";
    std::cout << "  " << (duration.count() / iterations) << " µs per operation\n";
    std::cout << "  " << (iterations * 1000000.0 / duration.count()) << " ops/sec\n";
    
    // Zero-copy performance
    std::vector<std::byte> buffer(serialized_size);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        msg.serialize(buffer);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "\nZero-copy serialization performance:\n";
    std::cout << "  " << iterations << " iterations in " << duration.count() << " µs\n";
    std::cout << "  " << (duration.count() / iterations) << " µs per operation\n";
    std::cout << "  " << (iterations * 1000000.0 / duration.count()) << " ops/sec\n";
    
    return 0;
}