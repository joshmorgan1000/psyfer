/**
 * @file 11_compress_then_encrypt.cpp
 * @brief Example demonstrating proper compress-then-encrypt workflows
 * 
 * This example shows:
 * - Why you should ALWAYS compress before encrypting
 * - Different compression algorithms (LZ4, FPC)
 * - Handling compression ratios
 * - Memory-efficient pipelines
 * - Error handling for both compression and encryption
 * 
 * IMPORTANT: Encrypted data has high entropy and cannot be compressed effectively.
 * Always compress first, then encrypt!
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>

using namespace psyfer;

/**
 * @brief Generate sample text data with repetition (compressible)
 */
std::vector<std::byte> generate_text_data(size_t size) {
    std::stringstream ss;
    const std::vector<std::string> phrases = {
        "The quick brown fox jumps over the lazy dog. ",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ",
        "Compression works well on repetitive data. ",
        "Psyfer provides fast and secure encryption. "
    };
    
    size_t written = 0;
    while (written < size) {
        ss << phrases[written % phrases.size()];
        written = ss.str().size();
    }
    
    std::string data = ss.str().substr(0, size);
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte*>(data.data()),
        reinterpret_cast<const std::byte*>(data.data() + data.size())
    );
}

/**
 * @brief Generate sample floating-point data (for FPC compression)
 */
std::vector<double> generate_float_data(size_t count) {
    std::vector<double> data;
    data.reserve(count);
    
    // Generate smooth sensor-like data with patterns
    double value = 100.0;
    double trend = 0.1;
    std::mt19937 gen(42);
    std::normal_distribution<double> noise(0.0, 0.5);
    
    for (size_t i = 0; i < count; ++i) {
        value += trend + noise(gen);
        if (value > 150.0) trend = -0.1;
        if (value < 50.0) trend = 0.1;
        data.push_back(value);
    }
    
    return data;
}

/**
 * @brief Print size statistics
 */
void print_statistics(const std::string& label, size_t original, size_t compressed, size_t encrypted) {
    std::cout << "\n" << label << " Statistics:\n";
    std::cout << "  Original size:    " << std::setw(8) << original << " bytes\n";
    std::cout << "  Compressed size:  " << std::setw(8) << compressed << " bytes ";
    std::cout << "(" << std::fixed << std::setprecision(1) 
              << (100.0 * compressed / original) << "%)\n";
    std::cout << "  Encrypted size:   " << std::setw(8) << encrypted << " bytes\n";
    std::cout << "  Compression ratio: " << std::setprecision(2) 
              << (double(original) / compressed) << ":1\n";
}

/**
 * @brief Example 1: LZ4 compression followed by AES-256-GCM encryption
 */
void example_lz4_then_aes() {
    std::cout << "\n=== Example 1: LZ4 Compression + AES-256-GCM Encryption ===\n";
    
    // Generate compressible text data
    auto original_data = generate_text_data(10000);
    std::cout << "Generated " << original_data.size() << " bytes of text data\n";
    
    // Step 1: Compress the data
    lz4 compressor;
    std::vector<std::byte> compressed_data(compressor.max_compressed_size(original_data.size()));
    
    auto compress_result = compressor.compress(original_data, compressed_data);
    if (!compress_result) {
        std::cerr << "Compression failed: " << compress_result.error().message() << "\n";
        return;
    }
    
    size_t compressed_size = compress_result.value();
    compressed_data.resize(compressed_size);
    
    std::cout << "Compressed to " << compressed_size << " bytes\n";
    
    // Step 2: Encrypt the compressed data
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    std::array<std::byte, 12> nonce;
    secure_random::generate(nonce);
    
    std::array<std::byte, 16> tag;
    psyfer::aes256_gcm cipher;
    
    // Make a copy for encryption (to preserve compressed data for comparison)
    std::vector<std::byte> encrypted_data = compressed_data;
    
    auto encrypt_err = cipher.encrypt(encrypted_data, key.span(), nonce, tag);
    if (encrypt_err) {
        std::cerr << "Encryption failed: " << encrypt_err.message() << "\n";
        return;
    }
    
    print_statistics("LZ4 + AES-256-GCM", original_data.size(), compressed_size, encrypted_data.size());
    
    // Step 3: Decrypt and decompress
    std::cout << "\nDecrypting and decompressing...\n";
    
    // Decrypt
    auto decrypt_err = cipher.decrypt(encrypted_data, key.span(), nonce, tag);
    if (decrypt_err) {
        std::cerr << "Decryption failed: " << decrypt_err.message() << "\n";
        return;
    }
    
    // Decompress
    std::vector<std::byte> decompressed_data(original_data.size());
    auto decompress_result = compressor.decompress(encrypted_data, decompressed_data);
    if (!decompress_result) {
        std::cerr << "Decompression failed: " << decompress_result.error().message() << "\n";
        return;
    }
    
    // Verify
    bool matches = (decompressed_data == original_data);
    std::cout << "Data integrity check: " << (matches ? "✅ PASSED" : "❌ FAILED") << "\n";
}

/**
 * @brief Example 2: FPC compression for floating-point data + ChaCha20
 */
void example_fpc_then_chacha() {
    std::cout << "\n=== Example 2: FPC Compression + ChaCha20-Poly1305 Encryption ===\n";
    
    // Generate floating-point sensor data
    auto float_data = generate_float_data(1000);
    size_t original_size = float_data.size() * sizeof(double);
    std::cout << "Generated " << float_data.size() << " floating-point values (" 
              << original_size << " bytes)\n";
    
    // Step 1: Compress with FPC
    auto compressed_data = psyfer::fpc_compress(float_data);
    std::cout << "FPC compressed to " << compressed_data.size() << " bytes\n";
    
    // Convert compressed data to byte span for encryption
    std::span<std::byte> compressed_span(
        reinterpret_cast<std::byte*>(compressed_data.data()),
        compressed_data.size()
    );
    
    // Step 2: Encrypt the compressed data
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    std::array<std::byte, 12> nonce;
    secure_random::generate(nonce);
    
    std::array<std::byte, 16> tag;
    psyfer::chacha20_poly1305 cipher;
    
    auto encrypt_err = cipher.encrypt(compressed_span, key.span(), nonce, tag);
    if (encrypt_err) {
        std::cerr << "Encryption failed: " << encrypt_err.message() << "\n";
        return;
    }
    
    print_statistics("FPC + ChaCha20", original_size, compressed_data.size(), compressed_data.size());
    
    // Step 3: Decrypt and decompress
    std::cout << "\nDecrypting and decompressing...\n";
    
    // Decrypt
    auto decrypt_err = cipher.decrypt(compressed_span, key.span(), nonce, tag);
    if (decrypt_err) {
        std::cerr << "Decryption failed: " << decrypt_err.message() << "\n";
        return;
    }
    
    // Decompress
    std::vector<double> decompressed_data(float_data.size());
    size_t decompressed_count = psyfer::fpc_decompress(
        std::span<const uint8_t>(compressed_data),
        decompressed_data
    );
    
    if (decompressed_count != float_data.size()) {
        std::cerr << "Decompression size mismatch\n";
        return;
    }
    
    // Verify with tolerance for floating-point
    bool matches = true;
    for (size_t i = 0; i < float_data.size(); ++i) {
        if (std::abs(float_data[i] - decompressed_data[i]) > 1e-10) {
            matches = false;
            break;
        }
    }
    
    std::cout << "Data integrity check: " << (matches ? "✅ PASSED" : "❌ FAILED") << "\n";
    
    // Show sample values
    std::cout << "\nSample values (first 5):\n";
    for (size_t i = 0; i < 5 && i < float_data.size(); ++i) {
        std::cout << "  [" << i << "] Original: " << std::setprecision(6) << float_data[i]
                  << ", Recovered: " << decompressed_data[i] << "\n";
    }
}

/**
 * @brief Example 3: Pipeline with size estimation and buffer management
 */
void example_efficient_pipeline() {
    std::cout << "\n=== Example 3: Efficient Compress-Encrypt Pipeline ===\n";
    
    // This example shows how to efficiently manage buffers for a compress-then-encrypt pipeline
    
    struct DataPacket {
        std::vector<std::byte> payload;
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
        size_t original_size;
        size_t compressed_size;
        
        // Calculate total size for transmission
        size_t total_size() const {
            return sizeof(original_size) + sizeof(compressed_size) + 
                   nonce.size() + tag.size() + payload.size();
        }
    };
    
    // Generate test data
    auto original_data = generate_text_data(5000);
    std::cout << "Processing " << original_data.size() << " bytes of data\n";
    
    // Create encryption key
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) {
        std::cerr << "Failed to generate key\n";
        return;
    }
    auto key = std::move(key_result.value());
    
    // Function to process data through the pipeline
    auto process_data = [&key](const std::vector<std::byte>& input) -> std::optional<DataPacket> {
        DataPacket packet;
        packet.original_size = input.size();
        
        // Step 1: Estimate compressed size and allocate buffer
        lz4 compressor;
        size_t max_compressed = compressor.max_compressed_size(input.size());
        packet.payload.resize(max_compressed);
        
        // Step 2: Compress
        auto compress_result = compressor.compress(input, packet.payload);
        if (!compress_result) {
            std::cerr << "Compression failed\n";
            return std::nullopt;
        }
        
        packet.compressed_size = compress_result.value();
        packet.payload.resize(packet.compressed_size);
        
        // Step 3: Generate crypto parameters
        secure_random::generate(packet.nonce);
        
        // Step 4: Encrypt in place
        psyfer::aes256_gcm cipher;
        auto encrypt_err = cipher.encrypt(packet.payload, key.span(), packet.nonce, packet.tag);
        if (encrypt_err) {
            std::cerr << "Encryption failed\n";
            return std::nullopt;
        }
        
        return packet;
    };
    
    // Process the data
    auto start = std::chrono::high_resolution_clock::now();
    auto packet_opt = process_data(original_data);
    auto end = std::chrono::high_resolution_clock::now();
    
    if (!packet_opt) {
        std::cerr << "Pipeline failed\n";
        return;
    }
    
    auto& packet = packet_opt.value();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "\nPipeline Performance:\n";
    std::cout << "  Processing time: " << duration.count() << " µs\n";
    std::cout << "  Throughput: " << std::fixed << std::setprecision(2)
              << (original_data.size() / (duration.count() / 1e6) / 1e6) << " MB/s\n";
    
    std::cout << "\nPacket Structure:\n";
    std::cout << "  Original size:    " << packet.original_size << " bytes\n";
    std::cout << "  Compressed size:  " << packet.compressed_size << " bytes\n";
    std::cout << "  Encrypted size:   " << packet.payload.size() << " bytes\n";
    std::cout << "  Total packet:     " << packet.total_size() << " bytes\n";
    std::cout << "  Overhead:         " << (packet.total_size() - packet.compressed_size) << " bytes\n";
    
    // Reverse pipeline: decrypt then decompress
    auto reverse_process = [&key](DataPacket& packet) -> std::optional<std::vector<std::byte>> {
        // Step 1: Decrypt
        psyfer::aes256_gcm cipher;
        auto decrypt_err = cipher.decrypt(packet.payload, key.span(), packet.nonce, packet.tag);
        if (decrypt_err) {
            std::cerr << "Decryption failed\n";
            return std::nullopt;
        }
        
        // Step 2: Decompress
        std::vector<std::byte> decompressed(packet.original_size);
        lz4 decompressor;
        
        // Note: After decryption, payload contains compressed data
        std::span<const std::byte> compressed_span(packet.payload.data(), packet.compressed_size);
        auto decompress_result = decompressor.decompress(compressed_span, decompressed);
        if (!decompress_result) {
            std::cerr << "Decompression failed\n";
            return std::nullopt;
        }
        
        return decompressed;
    };
    
    // Test reverse pipeline
    std::cout << "\nTesting reverse pipeline...\n";
    auto recovered_opt = reverse_process(packet);
    if (recovered_opt && recovered_opt.value() == original_data) {
        std::cout << "✅ Data successfully recovered through pipeline!\n";
    } else {
        std::cout << "❌ Pipeline test failed!\n";
    }
}

/**
 * @brief Example 4: Demonstrating why NOT to encrypt then compress
 */
void example_wrong_order() {
    std::cout << "\n=== Example 4: Why NOT to Encrypt Then Compress ===\n";
    std::cout << "(This shows what happens when you do it wrong)\n\n";
    
    // Generate test data
    auto original_data = generate_text_data(5000);
    
    // Create key and crypto parameters
    auto key_result = psyfer::secure_key_256::generate();
    if (!key_result) return;
    auto key = std::move(key_result.value());
    
    std::array<std::byte, 12> nonce;
    secure_random::generate(nonce);
    std::array<std::byte, 16> tag;
    
    // WRONG WAY: Encrypt first
    std::vector<std::byte> encrypted_data = original_data;
    psyfer::aes256_gcm cipher;
    cipher.encrypt(encrypted_data, key.span(), nonce, tag);
    
    // Try to compress encrypted data
    lz4 compressor;
    std::vector<std::byte> compressed_encrypted(compressor.max_compressed_size(encrypted_data.size()));
    auto result1 = compressor.compress(encrypted_data, compressed_encrypted);
    
    size_t wrong_way_size = result1 ? result1.value() : 0;
    
    // RIGHT WAY: Compress first
    std::vector<std::byte> compressed_data(compressor.max_compressed_size(original_data.size()));
    auto result2 = compressor.compress(original_data, compressed_data);
    size_t right_way_size = result2 ? result2.value() : 0;
    compressed_data.resize(right_way_size);
    
    // Then encrypt
    cipher.encrypt(compressed_data, key.span(), nonce, tag);
    
    std::cout << "Results:\n";
    std::cout << "  Original size:                " << original_data.size() << " bytes\n";
    std::cout << "\nWRONG (Encrypt→Compress):\n";
    std::cout << "  After encryption:             " << encrypted_data.size() << " bytes\n";
    std::cout << "  After 'compression':          " << wrong_way_size << " bytes\n";
    std::cout << "  Compression ratio:            " << std::fixed << std::setprecision(2)
              << (wrong_way_size > 0 ? double(encrypted_data.size()) / wrong_way_size : 0) << ":1\n";
    std::cout << "  ❌ Encrypted data has high entropy - compression is ineffective!\n";
    
    std::cout << "\nRIGHT (Compress→Encrypt):\n";
    std::cout << "  After compression:            " << right_way_size << " bytes\n";
    std::cout << "  After encryption:             " << compressed_data.size() << " bytes\n";
    std::cout << "  Compression ratio:            " << std::fixed << std::setprecision(2)
              << double(original_data.size()) / right_way_size << ":1\n";
    std::cout << "  ✅ Compression works well on original data!\n";
    
    std::cout << "\nSpace saved by correct order: " 
              << (wrong_way_size - right_way_size) << " bytes ("
              << int(100.0 * (wrong_way_size - right_way_size) / wrong_way_size) << "%)\n";
}

int main() {
    std::cout << "Psyfer Compress-Then-Encrypt Examples\n";
    std::cout << "=====================================\n";
    
    try {
        example_lz4_then_aes();
        example_fpc_then_chacha();
        example_efficient_pipeline();
        example_wrong_order();
        
        std::cout << "\n✅ All examples completed successfully!\n";
        std::cout << "\nKey Takeaways:\n";
        std::cout << "1. ALWAYS compress before encrypting\n";
        std::cout << "2. Use LZ4 for general data, FPC for floating-point data\n";
        std::cout << "3. Plan buffer sizes based on max_compressed_size()\n";
        std::cout << "4. Consider the overhead of crypto metadata in your protocols\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}