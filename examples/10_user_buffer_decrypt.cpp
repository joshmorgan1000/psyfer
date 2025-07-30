/**
 * @file 10_user_buffer_decrypt.cpp
 * @brief Example demonstrating decryption into user-specified buffers
 * 
 * This example shows how to:
 * - Allocate your own buffers for decryption
 * - Handle buffer size calculations
 * - Decrypt data in-place
 * - Use different encryption algorithms with user buffers
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>

using namespace psyfer;

/**
 * @brief Print hex representation of data
 */
void print_hex(const std::string& label, std::span<const std::byte> data, size_t max_bytes = 32) {
    std::cout << label << " (first " << std::min(data.size(), max_bytes) << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(static_cast<uint8_t>(data[i])) << " ";
    }
    std::cout << std::dec << "\n";
}

/**
 * @brief Example 1: Basic decrypt to user buffer with AES-256-GCM
 */
void example_aes_gcm_user_buffer() {
    std::cout << "\n=== Example 1: AES-256-GCM Decrypt to User Buffer ===\n";
    
    // Generate a key and nonce
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    // Generate a random nonce
    std::array<std::byte, 12> nonce;
    auto nonce_err = secure_random::generate(nonce);
    if (nonce_err) {
        std::cerr << "Failed to generate nonce\n";
        return;
    }
    
    // Original data
    std::string original_text = "This is sensitive data that needs encryption and will be decrypted to a user buffer!";
    std::vector<std::byte> data(
        reinterpret_cast<const std::byte*>(original_text.data()),
        reinterpret_cast<const std::byte*>(original_text.data() + original_text.size())
    );
    
    // Make a copy for encryption (preserving original for comparison)
    std::vector<std::byte> encrypted_data = data;
    
    // Encrypt the data
    std::array<std::byte, 16> tag;
    psyfer::aes256_gcm cipher;
    
    auto encrypt_err = cipher.encrypt(encrypted_data, key.span(), nonce, tag);
    if (encrypt_err) {
        std::cerr << "Encryption failed: " << encrypt_err.message() << "\n";
        return;
    }
    
    print_hex("Encrypted data", encrypted_data);
    print_hex("Authentication tag", tag);
    
    // Now demonstrate decryption to user buffer
    // Method 1: Allocate exact size buffer
    std::cout << "\nMethod 1: Pre-allocated exact size buffer\n";
    {
        // User allocates buffer of exact size needed
        std::vector<std::byte> user_buffer(encrypted_data.size());
        
        // Copy encrypted data to user buffer
        std::memcpy(user_buffer.data(), encrypted_data.data(), encrypted_data.size());
        
        // Decrypt in the user buffer
        auto decrypt_err = cipher.decrypt(user_buffer, key.span(), nonce, tag);
        if (decrypt_err) {
            std::cerr << "Decryption failed: " << decrypt_err.message() << "\n";
            return;
        }
        
        // Verify decryption
        std::string decrypted_text(reinterpret_cast<char*>(user_buffer.data()), user_buffer.size());
        std::cout << "Decrypted text: " << decrypted_text << "\n";
        std::cout << "Matches original: " << (decrypted_text == original_text ? "YES" : "NO") << "\n";
    }
    
    // Method 2: Use a larger buffer (common in network protocols)
    std::cout << "\nMethod 2: Using a larger buffer (e.g., network packet buffer)\n";
    {
        // Simulate a fixed-size packet buffer
        constexpr size_t PACKET_BUFFER_SIZE = 4096;
        std::array<std::byte, PACKET_BUFFER_SIZE> packet_buffer{};
        
        // Copy encrypted data to beginning of packet buffer
        size_t data_size = encrypted_data.size();
        std::memcpy(packet_buffer.data(), encrypted_data.data(), data_size);
        
        // Create a span for just the data portion
        std::span<std::byte> data_span(packet_buffer.data(), data_size);
        
        // Decrypt the data portion
        auto decrypt_err = cipher.decrypt(data_span, key.span(), nonce, tag);
        if (decrypt_err) {
            std::cerr << "Decryption failed: " << decrypt_err.message() << "\n";
            return;
        }
        
        // Extract decrypted text
        std::string decrypted_text(reinterpret_cast<char*>(packet_buffer.data()), data_size);
        std::cout << "Decrypted text: " << decrypted_text << "\n";
        std::cout << "Buffer utilization: " << data_size << "/" << PACKET_BUFFER_SIZE << " bytes\n";
    }
}

/**
 * @brief Example 2: ChaCha20-Poly1305 with custom memory management
 */
void example_chacha20_custom_memory() {
    std::cout << "\n=== Example 2: ChaCha20-Poly1305 with Custom Memory Management ===\n";
    
    // Custom buffer allocator simulation
    class BufferPool {
    public:
        enum { BUFFER_SIZE = 1024 };
        enum { NUM_BUFFERS = 10 };
        
        BufferPool() {
            // Pre-allocate all buffers
            for (size_t i = 0; i < NUM_BUFFERS; ++i) {
                buffers_[i].fill(std::byte{0});
                available_[i] = true;
            }
        }
        
        std::span<std::byte> allocate() {
            for (size_t i = 0; i < NUM_BUFFERS; ++i) {
                if (available_[i]) {
                    available_[i] = false;
                    return buffers_[i];
                }
            }
            return {}; // No buffer available
        }
        
        void release(std::span<std::byte> buffer) {
            for (size_t i = 0; i < NUM_BUFFERS; ++i) {
                if (buffer.data() == buffers_[i].data()) {
                    available_[i] = true;
                    // Clear buffer for security
                    buffers_[i].fill(std::byte{0});
                    return;
                }
            }
        }
        
    private:
        std::array<std::array<std::byte, BUFFER_SIZE>, NUM_BUFFERS> buffers_;
        std::array<bool, NUM_BUFFERS> available_;
    };
    
    BufferPool pool;
    
    // Get encryption key
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    // Generate nonce
    std::array<std::byte, 12> nonce;
    auto nonce_err = secure_random::generate(nonce);
    if (nonce_err) {
        std::cerr << "Failed to generate nonce\n";
        return;
    }
    
    // Get a buffer from the pool
    auto buffer = pool.allocate();
    if (buffer.empty()) {
        std::cerr << "No buffer available from pool\n";
        return;
    }
    
    // Prepare data in the buffer
    std::string message = "Secret message using buffer pool!";
    size_t data_size = message.size();
    if (data_size > buffer.size()) {
        std::cerr << "Message too large for buffer\n";
        pool.release(buffer);
        return;
    }
    
    std::memcpy(buffer.data(), message.data(), data_size);
    std::span<std::byte> data_span(buffer.data(), data_size);
    
    // Encrypt in place
    std::array<std::byte, 16> tag;
    psyfer::chacha20_poly1305 cipher;
    
    auto encrypt_err = cipher.encrypt(data_span, key.span(), nonce, tag);
    if (encrypt_err) {
        std::cerr << "Encryption failed: " << encrypt_err.message() << "\n";
        pool.release(buffer);
        return;
    }
    
    std::cout << "Encrypted " << data_size << " bytes in pooled buffer\n";
    print_hex("Encrypted data", data_span);
    
    // Decrypt in place
    auto decrypt_err = cipher.decrypt(data_span, key.span(), nonce, tag);
    if (decrypt_err) {
        std::cerr << "Decryption failed: " << decrypt_err.message() << "\n";
        pool.release(buffer);
        return;
    }
    
    std::string decrypted(reinterpret_cast<char*>(buffer.data()), data_size);
    std::cout << "Decrypted message: " << decrypted << "\n";
    
    // Return buffer to pool
    pool.release(buffer);
    std::cout << "Buffer returned to pool\n";
}

/**
 * @brief Example 3: Handling variable-length data with user buffers
 */
void example_variable_length_data() {
    std::cout << "\n=== Example 3: Variable-Length Data with User Buffers ===\n";
    
    // Simulate receiving encrypted messages of different sizes
    struct EncryptedMessage {
        std::vector<std::byte> data;
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        size_t original_size; // Size before encryption
    };
    
    // Generate key
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    // Create some test messages
    std::vector<std::string> messages = {
        "Short msg",
        "This is a medium length message with more content",
        "This is a much longer message that contains a lot more data and would typically "
        "require a larger buffer to handle properly. It demonstrates how the system handles "
        "variable-length content efficiently."
    };
    
    std::vector<EncryptedMessage> encrypted_messages;
    psyfer::aes256_gcm cipher;
    
    // Encrypt all messages
    for (const auto& msg : messages) {
        EncryptedMessage enc_msg;
        enc_msg.original_size = msg.size();
        enc_msg.data.resize(msg.size());
        
        // Copy message to buffer
        std::memcpy(enc_msg.data.data(), msg.data(), msg.size());
        
        // Generate unique nonce for each message
        secure_random::generate(enc_msg.nonce);
        
        // Encrypt
        auto err = cipher.encrypt(enc_msg.data, key.span(), enc_msg.nonce, enc_msg.tag);
        if (err) {
            std::cerr << "Failed to encrypt message\n";
            continue;
        }
        
        encrypted_messages.push_back(std::move(enc_msg));
    }
    
    // Now decrypt using a single reusable buffer
    // Size it to handle the largest expected message
    constexpr size_t MAX_MESSAGE_SIZE = 1024;
    std::vector<std::byte> decrypt_buffer(MAX_MESSAGE_SIZE);
    
    std::cout << "Decrypting " << encrypted_messages.size() << " messages using a single buffer\n\n";
    
    for (size_t i = 0; i < encrypted_messages.size(); ++i) {
        const auto& enc_msg = encrypted_messages[i];
        
        // Check if buffer is large enough
        if (enc_msg.data.size() > decrypt_buffer.size()) {
            std::cerr << "Message " << i << " too large for buffer\n";
            continue;
        }
        
        // Copy encrypted data to decrypt buffer
        std::memcpy(decrypt_buffer.data(), enc_msg.data.data(), enc_msg.data.size());
        
        // Create span for actual data size
        std::span<std::byte> data_span(decrypt_buffer.data(), enc_msg.data.size());
        
        // Decrypt
        auto err = cipher.decrypt(data_span, key.span(), enc_msg.nonce, enc_msg.tag);
        if (err) {
            std::cerr << "Failed to decrypt message " << i << ": " << err.message() << "\n";
            continue;
        }
        
        // Extract decrypted message
        std::string decrypted(reinterpret_cast<char*>(decrypt_buffer.data()), enc_msg.original_size);
        std::cout << "Message " << i << " (" << enc_msg.original_size << " bytes): " 
                  << decrypted.substr(0, 50) << (decrypted.size() > 50 ? "..." : "") << "\n";
    }
    
    std::cout << "\nBuffer statistics:\n";
    std::cout << "- Single buffer size: " << decrypt_buffer.size() << " bytes\n";
    std::cout << "- Total messages processed: " << encrypted_messages.size() << "\n";
    std::cout << "- Memory saved vs individual buffers: " 
              << (messages[0].size() + messages[1].size() + messages[2].size() - decrypt_buffer.size()) 
              << " bytes\n";
}

int main() {
    std::cout << "Psyfer User Buffer Decryption Examples\n";
    std::cout << "=====================================\n";
    
    try {
        example_aes_gcm_user_buffer();
        example_chacha20_custom_memory();
        example_variable_length_data();
        
        std::cout << "\n✅ All examples completed successfully!\n";
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}