/**
 * @file 12_psy_c_generated.cpp
 * @brief Example demonstrating psy-c generated code usage
 * 
 * This example shows:
 * - How to use psy-c generated serialization classes
 * - Encrypting/decrypting structured data
 * - Working with different encryption annotations
 * - Memory management for encrypted objects
 * - Integration with compress+encrypt workflows
 * 
 * NOTE: This example simulates what psy-c would generate. In real usage,
 * you would run the psy-c compiler on your schema files to generate these classes.
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <memory>

using namespace psyfer;

/**
 * @brief Example schema that would be defined in a .psy file:
 * 
 * struct UserProfile {
 *     string username;
 *     @encrypt(aes256_gcm) string email;
 *     @encrypt(aes256_gcm) uint32 age;
 *     vector<string> interests;
 * }
 * 
 * @encrypt(chacha20_poly1305)
 * struct SecureMessage {
 *     uint64 timestamp;
 *     string sender;
 *     @compress(lz4) string content;
 *     bytes attachment;
 * }
 * 
 * struct Transaction {
 *     string id;
 *     @encrypt(aes256_gcm) double amount;
 *     @encrypt(aes256_gcm) string account_number;
 *     @hash(sha256) string description;
 * }
 */

// Simulated psy-c generated code follows...

/**
 * @brief Generated base class for psy-c objects
 */
class PsyObject {
public:
    virtual ~PsyObject() = default;
    
    /**
     * @brief Get the size needed for encrypted serialization
     */
    virtual size_t encrypted_size() const = 0;
    
    /**
     * @brief Serialize and encrypt to a buffer
     * @param buffer Output buffer (must be at least encrypted_size() bytes)
     * @param key Encryption key
     * @return Bytes written or 0 on error
     */
    virtual size_t encrypt(std::span<std::byte> buffer, 
                          std::span<const std::byte, 32> key) const = 0;
    
    /**
     * @brief Decrypt and deserialize from a buffer
     * @param buffer Input buffer
     * @param key Decryption key
     * @return Bytes consumed or 0 on error
     */
    virtual size_t decrypt(std::span<const std::byte> buffer,
                          std::span<const std::byte, 32> key) = 0;
                          
    /**
     * @brief Convenience method to encrypt and return a vector
     * @param key Encryption key
     * @return Encrypted data as a vector, or empty vector on error
     */
    [[nodiscard]] std::vector<std::byte> encrypt_to_vector(
        std::span<const std::byte> key
    ) const {
        // Check key size
        if (key.size() != 32) {
            return {};
        }
        
        // Get required buffer size
        size_t required_size = encrypted_size();
        if (required_size == 0) {
            return {};
        }
        
        // Allocate buffer
        std::vector<std::byte> buffer(required_size);
        
        // Call the virtual encrypt method
        size_t written = encrypt(buffer, std::span<const std::byte, 32>(key.data(), 32));
        
        // Check if encryption succeeded
        if (written == 0) {
            return {};
        }
        
        // Resize to actual size written
        buffer.resize(written);
        
        return buffer;
    }
    
    // Note: PsyferContext integration is done through direct calls on derived classes
};

/**
 * @brief Generated UserProfile class
 */
class UserProfile : public PsyObject {
public:
    std::string username;
    std::string email;  // @encrypt(aes256_gcm)
    uint32_t age;       // @encrypt(aes256_gcm)
    std::vector<std::string> interests;
    
    // Static decrypt method for PsyferContext
    static size_t decrypt(std::span<const std::byte> source_buffer,
                         UserProfile* target,
                         std::span<const std::byte, 32> key) {
        return target->decrypt(source_buffer, key);
    }
    
    // Generated methods
    size_t encrypted_size() const override {
        size_t size = 0;
        
        // Username (unencrypted)
        size += sizeof(uint32_t); // field header
        size += sizeof(uint32_t) + username.size(); // length + string
        
        // Email (encrypted)
        size += sizeof(uint32_t); // field header
        size += sizeof(uint32_t) + email.size() + 12 + 16; // length + data + nonce + tag
        
        // Age (encrypted)
        size += sizeof(uint32_t); // field header
        size += sizeof(uint32_t) + 4 + 12 + 16; // length + uint32 + nonce + tag
        
        // Interests
        size += sizeof(uint32_t); // field header
        size += sizeof(uint32_t); // count
        for (const auto& interest : interests) {
            size += sizeof(uint32_t) + interest.size(); // length + string
        }
        
        return size;
    }
    
    size_t encrypt(std::span<std::byte> buffer, 
                   std::span<const std::byte, 32> key) const override {
        std::vector<std::byte> temp_buffer;
        temp_buffer.reserve(buffer.size());
        BufferWriter writer(temp_buffer);
        aes256_gcm cipher;
        
        // Field 1: username (unencrypted)
        writer.write_field_header(1, WireType::BYTES);
        writer.write_string_field(username);
        
        // Field 2: email (encrypted)
        {
            std::vector<std::byte> email_bytes(
        reinterpret_cast<const std::byte*>(email.data()),
        reinterpret_cast<const std::byte*>(email.data() + email.size())
    );
            std::array<std::byte, 12> nonce;
            std::array<std::byte, 16> tag;
            secure_random::generate(nonce);
            
            cipher.encrypt(email_bytes, key, nonce, tag);
            
            // Write encrypted field
            writer.write_field_header(2, WireType::BYTES);
            writer.write_u32(static_cast<uint32_t>(email_bytes.size() + nonce.size() + tag.size()));
            writer.write_bytes(nonce);
            writer.write_bytes(tag);
            writer.write_bytes(email_bytes);
        }
        
        // Field 3: age (encrypted)
        {
            std::array<std::byte, 4> age_bytes;
            std::memcpy(age_bytes.data(), &age, sizeof(age));
            std::array<std::byte, 12> nonce;
            std::array<std::byte, 16> tag;
            secure_random::generate(nonce);
            
            cipher.encrypt(age_bytes, key, nonce, tag);
            
            writer.write_field_header(3, WireType::BYTES);
            writer.write_u32(static_cast<uint32_t>(age_bytes.size() + nonce.size() + tag.size()));
            writer.write_bytes(nonce);
            writer.write_bytes(tag);
            writer.write_bytes(age_bytes);
        }
        
        // Field 4: interests (unencrypted)
        writer.write_field_header(4, WireType::BYTES);
        writer.write_u32(static_cast<uint32_t>(interests.size()));
        for (const auto& interest : interests) {
            writer.write_string_field(interest);
        }
        
        // Copy to output buffer
        size_t written = writer.position();
        if (written > buffer.size()) return 0;
        std::memcpy(buffer.data(), temp_buffer.data(), written);
        return written;
    }
    
    size_t decrypt(std::span<const std::byte> buffer,
                   std::span<const std::byte, 32> key) override {
        BufferReader reader(buffer);
        aes256_gcm cipher;
        
        while (reader.has_more()) {
            auto field_header = reader.read_u32();
            if (!field_header) break;
            uint32_t field_number = *field_header >> 3;
            auto wire_type = static_cast<WireType>(*field_header & 0x7);
            
            switch (field_number) {
                case 1: { // username
                    auto str = reader.read_string_field();
                    if (str) username = std::string(*str);
                    break;
                }
                
                case 2: { // email (encrypted)
                    auto encrypted = reader.read_bytes_field();
                    if (!encrypted || encrypted->size() < 28) break;
                    
                    std::array<std::byte, 12> nonce;
                    std::array<std::byte, 16> tag;
                    std::memcpy(nonce.data(), encrypted->data(), 12);
                    std::memcpy(tag.data(), encrypted->data() + 12, 16);
                    
                    std::vector<std::byte> email_data(
                        encrypted->begin() + 28, encrypted->end()
                    );
                    
                    if (cipher.decrypt(email_data, key, nonce, tag) == std::error_code{}) {
                        email = std::string(
                            reinterpret_cast<char*>(email_data.data()),
                            email_data.size()
                        );
                    }
                    break;
                }
                
                case 3: { // age (encrypted)
                    auto encrypted = reader.read_bytes_field();
                    if (!encrypted || encrypted->size() != 32) break;
                    
                    std::array<std::byte, 12> nonce;
                    std::array<std::byte, 16> tag;
                    std::array<std::byte, 4> age_bytes;
                    std::memcpy(nonce.data(), encrypted->data(), 12);
                    std::memcpy(tag.data(), encrypted->data() + 12, 16);
                    std::memcpy(age_bytes.data(), encrypted->data() + 28, 4);
                    
                    if (cipher.decrypt(age_bytes, key, nonce, tag) == std::error_code{}) {
                        std::memcpy(&age, age_bytes.data(), sizeof(age));
                    }
                    break;
                }
                
                case 4: { // interests
                    auto count = reader.read_u32();
                    if (!count) break;
                    
                    interests.clear();
                    interests.reserve(*count);
                    for (size_t i = 0; i < *count; ++i) {
                        auto str = reader.read_string_field();
                        if (str) interests.emplace_back(*str);
                    }
                    break;
                }
                
                default:
                    // Skip unknown fields
                    if (wire_type == psyfer::WireType::BYTES) {
                        auto data = reader.read_bytes_field();
                    } else if (wire_type == psyfer::WireType::VARINT) {
                        reader.read_u32();
                    }
                    break;
            }
        }
        
        return reader.position();
    }
};

/**
 * @brief Generated SecureMessage class (entire struct encrypted)
 */
class SecureMessage : public PsyObject {
public:
    uint64_t timestamp;
    std::string sender;
    std::string content;  // @compress(lz4)
    std::vector<std::byte> attachment;
    
    // Static decrypt method for PsyferContext
    static size_t decrypt(std::span<const std::byte> source_buffer,
                         SecureMessage* target,
                         std::span<const std::byte, 32> key) {
        return target->decrypt(source_buffer, key);
    }
    
    size_t encrypted_size() const override {
        // Calculate inner size
        size_t inner_size = 0;
        inner_size += sizeof(uint32_t) + sizeof(uint64_t); // field header + timestamp
        inner_size += sizeof(uint32_t) + sizeof(uint32_t) + sender.size(); // field header + length + string
        
        // Compressed content
        psyfer::lz4 compressor;
        size_t max_compressed = compressor.max_compressed_size(content.size());
        inner_size += sizeof(uint32_t) + sizeof(uint32_t) + max_compressed; // field header + length + bytes
        
        inner_size += sizeof(uint32_t) + sizeof(uint32_t) + attachment.size(); // field header + length + bytes
        
        // Add encryption overhead (nonce + tag)
        return inner_size + 12 + 16;
    }
    
    size_t encrypt(std::span<std::byte> buffer, 
                   std::span<const std::byte, 32> key) const override {
        // First serialize to temporary buffer
        std::vector<std::byte> temp_buffer(encrypted_size());
        BufferWriter writer(temp_buffer);
        
        // Field 1: timestamp
        writer.write_field_header(1, WireType::VARINT);
        writer.write_u64(timestamp);
        
        // Field 2: sender
        writer.write_field_header(2, WireType::BYTES);
        writer.write_string_field(sender);
        
        // Field 3: content (compressed)
        {
            psyfer::lz4 compressor;
            std::span<const std::byte> content_bytes(
                reinterpret_cast<const std::byte*>(content.data()),
                content.size()
            );
            
            std::vector<std::byte> compressed(compressor.max_compressed_size(content.size()));
            auto result = compressor.compress(content_bytes, compressed);
            if (result) {
                compressed.resize(result.value());
                writer.write_field_header(3, WireType::BYTES);
                writer.write_bytes_field(compressed);
            }
        }
        
        // Field 4: attachment
        writer.write_field_header(4, WireType::BYTES);
        writer.write_bytes_field(attachment);
        
        // Now encrypt the entire message
        size_t serialized_size = writer.position();
        std::span<std::byte> data_to_encrypt(temp_buffer.data(), serialized_size);
        
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        secure_random::generate(nonce);
        
        chacha20_poly1305 cipher;
        auto err = cipher.encrypt(data_to_encrypt, key, nonce, tag);
        if (err) return 0;
        
        // Write to output buffer
        if (buffer.size() < serialized_size + 28) return 0;
        
        std::memcpy(buffer.data(), nonce.data(), 12);
        std::memcpy(buffer.data() + 12, tag.data(), 16);
        std::memcpy(buffer.data() + 28, data_to_encrypt.data(), serialized_size);
        
        return serialized_size + 28;
    }
    
    size_t decrypt(std::span<const std::byte> buffer,
                   std::span<const std::byte, 32> key) override {
        if (buffer.size() < 28) return 0;
        
        // Extract crypto parameters
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        std::memcpy(nonce.data(), buffer.data(), 12);
        std::memcpy(tag.data(), buffer.data() + 12, 16);
        
        // Decrypt the payload
        std::vector<std::byte> decrypted(buffer.size() - 28);
        std::memcpy(decrypted.data(), buffer.data() + 28, decrypted.size());
        
        chacha20_poly1305 cipher;
        auto err = cipher.decrypt(decrypted, key, nonce, tag);
        if (err) return 0;
        
        // Parse decrypted data
        BufferReader reader(decrypted);
        
        while (reader.has_more()) {
            auto field_header = reader.read_u32();
            if (!field_header) break;
            uint32_t field_number = *field_header >> 3;
            auto wire_type = static_cast<WireType>(*field_header & 0x7);
            
            switch (field_number) {
                case 1: // timestamp
                    if (auto val = reader.read_u64()) {
                        timestamp = *val;
                    }
                    break;
                    
                case 2: // sender
                    if (auto str = reader.read_string_field()) {
                        sender = std::string(*str);
                    }
                    break;
                    
                case 3: { // content (compressed)
                    if (auto compressed = reader.read_bytes_field()) {
                        psyfer::lz4 decompressor;
                        std::vector<std::byte> decompressed(content.capacity() * 2);
                        
                        auto result = decompressor.decompress(*compressed, decompressed);
                        if (result) {
                            content = std::string(
                                reinterpret_cast<char*>(decompressed.data()),
                                result.value()
                            );
                        }
                    }
                    break;
                }
                
                case 4: // attachment
                    if (auto bytes = reader.read_bytes_field()) {
                        attachment.assign(bytes->begin(), bytes->end());
                    }
                    break;
            }
        }
        
        return buffer.size();
    }
};

/**
 * @brief Example usage of psy-c generated objects
 */
void example_user_profile() {
    std::cout << "\n=== Example 1: UserProfile with Field-Level Encryption ===\n";
    
    // Create and populate a user profile
    UserProfile profile;
    profile.username = "alice_wonderland";
    profile.email = "alice@example.com";
    profile.age = 28;
    profile.interests = {"cryptography", "chess", "tea parties"};
    
    // Generate encryption key
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    // Serialize and encrypt
    size_t needed_size = profile.encrypted_size();
    std::vector<std::byte> encrypted_buffer(needed_size);
    
    size_t written = profile.encrypt(encrypted_buffer, key.span());
    std::cout << "Serialized UserProfile to " << written << " bytes\n";
    std::cout << "  - Username (plain): " << profile.username << "\n";
    std::cout << "  - Email (encrypted): " << profile.email << "\n";
    std::cout << "  - Age (encrypted): " << profile.age << "\n";
    
    // Decrypt into a new object
    UserProfile decrypted_profile;
    size_t consumed = decrypted_profile.decrypt(encrypted_buffer, key.span());
    
    std::cout << "\nDecrypted UserProfile (" << consumed << " bytes):\n";
    std::cout << "  - Username: " << decrypted_profile.username << "\n";
    std::cout << "  - Email: " << decrypted_profile.email << "\n";
    std::cout << "  - Age: " << decrypted_profile.age << "\n";
    std::cout << "  - Interests: ";
    for (const auto& interest : decrypted_profile.interests) {
        std::cout << interest << " ";
    }
    std::cout << "\n";
}

/**
 * @brief Example with compressed and encrypted message
 */
void example_secure_message() {
    std::cout << "\n=== Example 2: SecureMessage with Compression + Encryption ===\n";
    
    // Create a message with compressible content
    SecureMessage msg;
    msg.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    msg.sender = "bob@example.com";
    msg.content = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                  "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
                  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                  "This repetitive text compresses well!";
    msg.attachment = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    
    // Generate key
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) return;
    auto key = std::move(key_result.value());
    
    // Encrypt
    std::vector<std::byte> buffer(msg.encrypted_size());
    size_t encrypted_size = msg.encrypt(buffer, key.span());
    buffer.resize(encrypted_size);
    
    std::cout << "Original content size: " << msg.content.size() << " bytes\n";
    std::cout << "Total encrypted size: " << encrypted_size << " bytes\n";
    std::cout << "Compression + encryption overhead: " 
              << (int(encrypted_size) - int(msg.content.size())) << " bytes\n";
    
    // Decrypt
    SecureMessage decrypted;
    decrypted.decrypt(buffer, key.span());
    
    std::cout << "\nDecrypted message:\n";
    std::cout << "  Timestamp: " << decrypted.timestamp << "\n";
    std::cout << "  Sender: " << decrypted.sender << "\n";
    std::cout << "  Content: " << decrypted.content.substr(0, 50) << "...\n";
    std::cout << "  Attachment size: " << decrypted.attachment.size() << " bytes\n";
}

// Helper struct for packet management (needs to be outside function for template)
struct Packet {
    static constexpr size_t PACKET_SIZE = 1024;
    std::array<std::byte, PACKET_SIZE> data;
    size_t used = 0;
    
    bool add_object(const PsyObject& obj, std::span<const std::byte, 32> key) {
        size_t needed = obj.encrypted_size();
        if (used + needed + sizeof(uint16_t) > PACKET_SIZE) {
            return false; // Not enough space
        }
        
        // Write size prefix
        uint16_t size_prefix = static_cast<uint16_t>(needed);
        std::memcpy(data.data() + used, &size_prefix, sizeof(size_prefix));
        used += sizeof(size_prefix);
        
        // Write encrypted object
        std::span<std::byte> dest(data.data() + used, needed);
        size_t written = obj.encrypt(dest, key);
        if (written == 0) return false;
        
        used += written;
        return true;
    }
        
    template<typename T>
    std::unique_ptr<T> extract_object(size_t& offset, std::span<const std::byte, 32> key) {
        if (offset + sizeof(uint16_t) > used) return nullptr;
        
        // Read size prefix
        uint16_t size;
        std::memcpy(&size, data.data() + offset, sizeof(size));
        offset += sizeof(size);
        
        if (offset + size > used) return nullptr;
        
        // Decrypt object
        auto obj = std::make_unique<T>();
        std::span<const std::byte> encrypted(data.data() + offset, size);
        size_t consumed = obj->decrypt(encrypted, key);
        if (consumed == 0) return nullptr;
        
        offset += consumed;
        return obj;
    }
};

/**
 * @brief Example showing buffer management for psy-c objects
 */
void example_buffer_management() {
    std::cout << "\n=== Example 3: Buffer Management for psy-c Objects ===\n";
    
    // Generate shared key
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) return;
    auto key = std::move(key_result.value());
    
    // Create packet and add multiple objects
    Packet packet;
    
    UserProfile user1;
    user1.username = "user1";
    user1.email = "user1@example.com";
    user1.age = 25;
    
    UserProfile user2;
    user2.username = "user2";
    user2.email = "user2@example.com";
    user2.age = 30;
    
    SecureMessage msg;
    msg.timestamp = 12345;
    msg.sender = "system";
    msg.content = "Hello, World!";
    
    // Add objects to packet
    bool added1 = packet.add_object(user1, key.span());
    bool added2 = packet.add_object(user2, key.span());
    bool added3 = packet.add_object(msg, key.span());
    
    std::cout << "Packet status:\n";
    std::cout << "  Added UserProfile 1: " << (added1 ? "YES" : "NO") << "\n";
    std::cout << "  Added UserProfile 2: " << (added2 ? "YES" : "NO") << "\n";
    std::cout << "  Added SecureMessage: " << (added3 ? "YES" : "NO") << "\n";
    std::cout << "  Packet utilization: " << packet.used << "/" << Packet::PACKET_SIZE << " bytes\n";
    
    // Extract objects from packet
    std::cout << "\nExtracting objects from packet...\n";
    size_t offset = 0;
    
    auto extracted_user1 = packet.extract_object<UserProfile>(offset, key.span());
    auto extracted_user2 = packet.extract_object<UserProfile>(offset, key.span());
    auto extracted_msg = packet.extract_object<SecureMessage>(offset, key.span());
    
    if (extracted_user1) {
        std::cout << "  Extracted user 1: " << extracted_user1->username << "\n";
    }
    if (extracted_user2) {
        std::cout << "  Extracted user 2: " << extracted_user2->username << "\n";
    }
    if (extracted_msg) {
        std::cout << "  Extracted message from: " << extracted_msg->sender << "\n";
    }
}

/**
 * @brief Example 4: Integration with PsyferContext
 */
void example_psyfer_context_integration() {
    std::cout << "\n=== Example 4: PsyferContext Integration ===\n";
    
    // Create a PsyferContext for easy key management
    auto ctx_result = PsyferContext::create({.identity_name = "psy-c Demo"});
    if (!ctx_result) {
        std::cerr << "Failed to create context\n";
        return;
    }
    auto& ctx = *ctx_result.value();
    
    // NOTE: In a real psy-c generated code, the classes would implement
    // the required concepts for PsyferContext integration.
    // For this demo, we'll use the objects' methods directly.
    
    // Create objects
    UserProfile profile;
    profile.username = "context_user";
    profile.email = "context@example.com";
    profile.age = 35;
    profile.interests = {"PsyferContext", "Easy encryption"};
    
    SecureMessage msg;
    msg.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    msg.sender = "system@psyfer";
    msg.content = "PsyferContext makes encryption easy! Just call encrypt_object() and decrypt_object().";
    
    std::cout << "Using PsyferContext for key management:\n";
    
    // Method 1: Using psy-c objects with PsyferContext keys
    {
        std::cout << "\nMethod 1: Using context's encryption key\n";
        
        // Get the encryption key from context
        auto key = ctx.get_psy_key();
        
        // Use the object's encrypt method
        size_t encrypted_size = profile.encrypted_size();
        std::vector<std::byte> encrypted_data(encrypted_size);
        size_t written = profile.encrypt(encrypted_data, key);
        encrypted_data.resize(written);
        
        std::cout << "Encrypted UserProfile: " << encrypted_data.size() << " bytes\n";
        
        // Decrypt using object's decrypt method
        UserProfile decrypted_profile;
        size_t consumed = decrypted_profile.decrypt(encrypted_data, key);
        
        if (consumed > 0) {
            std::cout << "Decrypted username: " << decrypted_profile.username << "\n";
            std::cout << "Decrypted email: " << decrypted_profile.email << "\n";
        } else {
            std::cerr << "Failed to decrypt profile\n";
        }
    }
    
    // Method 2: Using whole-object encryption
    {
        std::cout << "\nMethod 2: Whole-object encryption\n";
        
        auto key = ctx.get_psy_key();
        
        // Encrypt the message
        size_t msg_size = msg.encrypted_size();
        std::vector<std::byte> encrypted_msg(msg_size);
        size_t written = msg.encrypt(encrypted_msg, key);
        encrypted_msg.resize(written);
        
        std::cout << "Encrypted SecureMessage: " << encrypted_msg.size() << " bytes\n";
        
        // Decrypt the message
        SecureMessage decrypted_msg;
        size_t consumed = decrypted_msg.decrypt(encrypted_msg, key);
        
        if (consumed > 0) {
            std::cout << "Decrypted sender: " << decrypted_msg.sender << "\n";
            std::cout << "Decrypted content: " << decrypted_msg.content.substr(0, 50) << "...\n";
        } else {
            std::cerr << "Failed to decrypt message\n";
        }
    }
    
    // Demonstrate key rotation with psy-c objects
    std::cout << "\nKey rotation scenario:\n";
    
    // Encrypt with current keys
    auto key_before = ctx.get_psy_key();
    size_t size_before = profile.encrypted_size();
    std::vector<std::byte> encrypted_before(size_before);
    profile.encrypt(encrypted_before, key_before);
    
    // Rotate keys
    auto err = ctx.rotate_keys();
    if (err) {
        std::cerr << "Key rotation failed\n";
        return;
    }
    std::cout << "Keys rotated successfully\n";
    
    // Can still decrypt old data (in real implementation, would keep old keys)
    // For this demo, decryption will fail after rotation
    UserProfile decrypt_test;
    size_t consumed = decrypt_test.decrypt(encrypted_before, ctx.get_psy_key());
    if (consumed == 0) {
        std::cout << "Cannot decrypt with new keys (expected behavior)\n";
    }
    
    // Encrypt with new keys
    auto key_after = ctx.get_psy_key();
    size_t size_after = profile.encrypted_size();
    std::vector<std::byte> encrypted_after(size_after);
    size_t written_after = profile.encrypt(encrypted_after, key_after);
    encrypted_after.resize(written_after);
    
    std::cout << "Re-encrypted with new keys: " << encrypted_after.size() << " bytes\n";
}

/**
 * @brief Example 5: Batch operations with PsyferContext
 */
void example_batch_operations() {
    std::cout << "\n=== Example 5: Batch Operations ===\n";
    
    // Create context
    auto ctx_result = PsyferContext::create();
    if (!ctx_result) return;
    auto& ctx = *ctx_result.value();
    
    // Create multiple objects
    std::vector<UserProfile> users;
    for (int i = 0; i < 5; ++i) {
        UserProfile user;
        user.username = "user" + std::to_string(i);
        user.email = "user" + std::to_string(i) + "@example.com";
        user.age = 20 + i * 5;
        users.push_back(user);
    }
    
    // Batch encrypt
    std::vector<std::vector<std::byte>> encrypted_users;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (const auto& user : users) {
        size_t user_size = user.encrypted_size();
        std::vector<std::byte> encrypted(user_size);
        size_t written = user.encrypt(encrypted, ctx.get_psy_key());
        if (written > 0) {
            encrypted.resize(written);
            encrypted_users.push_back(std::move(encrypted));
        }
    }
    
    auto encrypt_time = std::chrono::high_resolution_clock::now() - start;
    
    std::cout << "Encrypted " << encrypted_users.size() << " users in "
              << std::chrono::duration_cast<std::chrono::microseconds>(encrypt_time).count()
              << " µs\n";
    
    // Batch decrypt
    std::vector<UserProfile> decrypted_users;
    start = std::chrono::high_resolution_clock::now();
    
    for (const auto& encrypted : encrypted_users) {
        UserProfile decrypted;
        size_t consumed = decrypted.decrypt(encrypted, ctx.get_psy_key());
        if (consumed > 0) {
            decrypted_users.push_back(std::move(decrypted));
        }
    }
    
    auto decrypt_time = std::chrono::high_resolution_clock::now() - start;
    
    std::cout << "Decrypted " << decrypted_users.size() << " users in "
              << std::chrono::duration_cast<std::chrono::microseconds>(decrypt_time).count()
              << " µs\n";
    
    // Verify
    bool all_match = true;
    for (size_t i = 0; i < users.size() && i < decrypted_users.size(); ++i) {
        if (users[i].username != decrypted_users[i].username) {
            all_match = false;
            break;
        }
    }
    
    std::cout << "Batch operation verification: " << (all_match ? "✅ SUCCESS" : "❌ FAILED") << "\n";
}

/**
 * @brief Example demonstrating the convenience encrypt method
 */
void example_convenience_encrypt() {
    std::cout << "\n5. Convenience Encrypt Method Example\n";
    std::cout << "-------------------------------------\n";
    
    // Create a user profile
    UserProfile profile;
    profile.username = "alice";
    profile.email = "alice@example.com";
    profile.age = 28;
    profile.interests = {"cryptography", "security", "privacy"};
    
    // Generate encryption key
    psyfer::secure_array<std::byte, 32> key;
    secure_random::generate(key);
    
    std::cout << "Original profile:\n";
    std::cout << "  Username: " << profile.username << "\n";
    std::cout << "  Email: " << profile.email << "\n";
    std::cout << "  Age: " << profile.age << "\n";
    std::cout << "  Interests: ";
    for (const auto& interest : profile.interests) {
        std::cout << interest << " ";
    }
    std::cout << "\n\n";
    
    // Test the convenience encrypt method
    std::cout << "Testing convenience encrypt method:\n";
    
    // Encrypt using the convenience method
    std::vector<std::byte> encrypted = profile.encrypt_to_vector(std::span<const std::byte, 32>(key.data(), 32));
    
    if (encrypted.empty()) {
        std::cout << "❌ Encryption failed - returned empty vector\n";
        return;
    }
    
    std::cout << "✅ Encrypted successfully\n";
    std::cout << "  Encrypted size: " << encrypted.size() << " bytes\n";
    
    // Verify by decrypting
    UserProfile decrypted_profile;
    size_t consumed = decrypted_profile.decrypt(encrypted, std::span<const std::byte, 32>(key.data(), 32));
    
    if (consumed == 0) {
        std::cout << "❌ Decryption failed\n";
        return;
    }
    
    std::cout << "✅ Decrypted successfully\n";
    std::cout << "  Consumed: " << consumed << " bytes\n";
    
    // Verify data integrity
    bool match = decrypted_profile.username == profile.username &&
                 decrypted_profile.email == profile.email &&
                 decrypted_profile.age == profile.age &&
                 decrypted_profile.interests == profile.interests;
    
    std::cout << "\nDecrypted profile:\n";
    std::cout << "  Username: " << decrypted_profile.username << "\n";
    std::cout << "  Email: " << decrypted_profile.email << "\n";
    std::cout << "  Age: " << decrypted_profile.age << "\n";
    std::cout << "  Interests: ";
    for (const auto& interest : decrypted_profile.interests) {
        std::cout << interest << " ";
    }
    std::cout << "\n";
    
    std::cout << "\nData integrity check: " << (match ? "✅ PASSED" : "❌ FAILED") << "\n";
    
    // Test with invalid key size
    std::cout << "\nTesting with invalid key size:\n";
    std::vector<std::byte> short_key(16);  // Too short
    secure_random::generate(short_key);
    
    std::vector<std::byte> result = profile.encrypt_to_vector(short_key);
    if (result.empty()) {
        std::cout << "✅ Correctly rejected invalid key size\n";
    } else {
        std::cout << "❌ Should have rejected invalid key size\n";
    }
}

int main() {
    std::cout << "Psyfer psy-c Generated Code Examples\n";
    std::cout << "===================================\n";
    std::cout << "\nNOTE: This demonstrates how psy-c generated code would work.\n";
    std::cout << "In real usage, these classes would be generated from .psy schema files.\n";
    
    try {
        example_user_profile();
        example_secure_message();
        example_buffer_management();
        example_psyfer_context_integration();
        example_batch_operations();
        example_convenience_encrypt();
        
        std::cout << "\n✅ All examples completed successfully!\n";
        
        std::cout << "\nKey Features Demonstrated:\n";
        std::cout << "1. Field-level encryption annotations\n";
        std::cout << "2. Whole-object encryption\n";
        std::cout << "3. Transparent compression before encryption\n";
        std::cout << "4. User-controlled buffer management\n";
        std::cout << "5. Efficient serialization with encryption\n";
        std::cout << "6. Seamless integration with PsyferContext\n";
        std::cout << "7. Batch operations for performance\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}