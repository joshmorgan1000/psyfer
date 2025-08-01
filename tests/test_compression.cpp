/**
 * @file test_compression.cpp
 * @brief Basic tests for LZ4 compression
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <random>

int main() {
    std::cout << "=== LZ4 Compression Tests ===" << std::endl;
    
    try {
        psyfer::lz4 compressor;
        
        // Test 1: Basic compression/decompression
        {
            std::cout << "\nTest 1: Basic text compression" << std::endl;
            
            std::string text = "The quick brown fox jumps over the lazy dog. "
                              "The quick brown fox jumps over the lazy dog. "
                              "The quick brown fox jumps over the lazy dog.";
            
            std::vector<std::byte> input(text.size());
            std::memcpy(input.data(), text.data(), text.size());
            
            size_t max_size = compressor.max_compressed_size(input.size());
            std::vector<std::byte> compressed(max_size);
            
            auto result = compressor.compress(input, compressed);
            if (!result) {
                std::cerr << "✗ Compression failed: " << result.error().message() << std::endl;
                return 1;
            }
            size_t compressed_size = *result;
            compressed.resize(compressed_size);
            
            std::cout << "Original size: " << input.size() << " bytes" << std::endl;
            std::cout << "Compressed size: " << compressed_size << " bytes" << std::endl;
            std::cout << "Compression ratio: " << (100.0 * compressed_size / input.size()) << "%" << std::endl;
            
            // Decompress
            std::vector<std::byte> decompressed(input.size());
            auto decomp_result = compressor.decompress(compressed, decompressed);
            if (!decomp_result) {
                std::cerr << "✗ Decompression failed: " << decomp_result.error().message() << std::endl;
                return 1;
            }
            size_t decompressed_size = *decomp_result;
            
            if (decompressed_size == input.size() && 
                std::memcmp(input.data(), decompressed.data(), input.size()) == 0) {
                std::cout << "✓ Compression/decompression successful" << std::endl;
            } else {
                std::cerr << "✗ Decompression failed" << std::endl;
                return 1;
            }
        }
        
        // Test 2: Empty data
        {
            std::cout << "\nTest 2: Empty data compression" << std::endl;
            
            std::vector<std::byte> empty;
            std::vector<std::byte> compressed(compressor.max_compressed_size(0));
            
            auto result = compressor.compress(empty, compressed);
            if (!result) {
                std::cerr << "✗ Empty compression failed: " << result.error().message() << std::endl;
                return 1;
            }
            size_t compressed_size = *result;
            
            if (compressed_size == 0) {
                std::cout << "✓ Empty data compressed to " << compressed_size << " bytes" << std::endl;
            } else {
                std::cerr << "✗ Empty data should compress to 0 bytes but got " << compressed_size << std::endl;
                return 1;
            }
        }
        
        // Test 3: Random data (should not compress well)
        {
            std::cout << "\nTest 3: Random data compression" << std::endl;
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            std::vector<std::byte> random_data(1024);
            for (auto& b : random_data) {
                b = static_cast<std::byte>(dis(gen));
            }
            
            size_t max_size = compressor.max_compressed_size(random_data.size());
            std::vector<std::byte> compressed(max_size);
            
            auto result = compressor.compress(random_data, compressed);
            if (!result) {
                std::cerr << "✗ Random data compression failed: " << result.error().message() << std::endl;
                return 1;
            }
            size_t compressed_size = *result;
            compressed.resize(compressed_size);
            
            std::cout << "Random data size: " << random_data.size() << " bytes" << std::endl;
            std::cout << "Compressed size: " << compressed_size << " bytes" << std::endl;
            std::cout << "Compression ratio: " << (100.0 * compressed_size / random_data.size()) << "%" << std::endl;
            
            // Should not compress well (likely > 100%)
            if (compressed_size >= random_data.size()) {
                std::cout << "✓ Random data did not compress (as expected)" << std::endl;
            }
            
            // But should still decompress correctly
            std::vector<std::byte> decompressed(random_data.size());
            auto decomp_result = compressor.decompress(compressed, decompressed);
            if (!decomp_result) {
                std::cerr << "✗ Decompression failed: " << decomp_result.error().message() << std::endl;
                return 1;
            }
            size_t decompressed_size = *decomp_result;
            
            if (decompressed_size == random_data.size() && 
                std::memcmp(random_data.data(), decompressed.data(), random_data.size()) == 0) {
                std::cout << "✓ Random data decompression successful" << std::endl;
            } else {
                std::cerr << "✗ Random data decompression failed" << std::endl;
                return 1;
            }
        }
        
        // Test 4: Highly compressible data
        {
            std::cout << "\nTest 4: Highly compressible data" << std::endl;
            
            std::vector<std::byte> zeros(1000, std::byte{0});
            
            size_t max_size = compressor.max_compressed_size(zeros.size());
            std::vector<std::byte> compressed(max_size);
            
            auto result = compressor.compress(zeros, compressed);
            if (!result) {
                std::cerr << "✗ Zeros compression failed: " << result.error().message() << std::endl;
                return 1;
            }
            size_t compressed_size = *result;
            
            std::cout << "Zeros size: " << zeros.size() << " bytes" << std::endl;
            std::cout << "Compressed size: " << compressed_size << " bytes" << std::endl;
            std::cout << "Compression ratio: " << (100.0 * compressed_size / zeros.size()) << "%" << std::endl;
            
            if (compressed_size < zeros.size()) { // Should compress at least somewhat
                std::cout << "✓ Highly compressible data compressed" << std::endl;
            } else {
                std::cerr << "✗ Compression failed - compressed size: " << compressed_size << " >= original: " << zeros.size() << std::endl;
                return 1;
            }
        }
        
        std::cout << "\n✓ All compression tests passed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}