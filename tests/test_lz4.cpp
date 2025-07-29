/**
 * @file test_lz4.cpp
 * @brief Tests for LZ4 compression implementation
 */

#include <psyfer.hpp>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <vector>
#include <random>
#include <chrono>

/**
 * @brief Print compression statistics
 */
void print_stats(const std::string& test_name, size_t original, size_t compressed) {
    double ratio = static_cast<double>(original) / compressed;
    double percent = (1.0 - static_cast<double>(compressed) / original) * 100;
    
    std::cout << test_name << ":" << std::endl;
    std::cout << "  Original:   " << original << " bytes" << std::endl;
    std::cout << "  Compressed: " << compressed << " bytes" << std::endl;
    std::cout << "  Ratio:      " << std::fixed << std::setprecision(2) << ratio << ":1" << std::endl;
    std::cout << "  Saved:      " << std::fixed << std::setprecision(1) << percent << "%" << std::endl;
}

/**
 * @brief Test basic LZ4 compression/decompression
 */
void test_lz4_basic() {
    std::cout << "Testing basic LZ4 compression..." << std::endl;
    
    psyfer::compression::lz4 compressor;
    
    // Test with simple repetitive data
    {
        std::string input = "Hello World! Hello World! Hello World! Hello World!";
        std::vector<std::byte> input_bytes;
        input_bytes.reserve(input.size());
        for (char c : input) {
            input_bytes.push_back(static_cast<std::byte>(c));
        }
        
        // Compress
        std::vector<std::byte> compressed(compressor.max_compressed_size(input_bytes.size()));
        auto result = compressor.compress(input_bytes, compressed);
        assert(result.has_value());
        compressed.resize(*result);
        
        print_stats("Repetitive text", input_bytes.size(), compressed.size());
        
        // Decompress
        std::vector<std::byte> decompressed(input_bytes.size() * 2);  // Extra space
        auto decomp_result = compressor.decompress(compressed, decompressed);
        assert(decomp_result.has_value());
        decompressed.resize(*decomp_result);
        
        // Verify
        assert(decompressed == input_bytes);
        std::cout << "✓ Compression/decompression successful" << std::endl;
    }
}

/**
 * @brief Test LZ4 with various data patterns
 */
void test_lz4_patterns() {
    std::cout << "\nTesting LZ4 with various patterns..." << std::endl;
    
    psyfer::compression::lz4 compressor;
    
    // All zeros (highly compressible)
    {
        std::vector<std::byte> zeros(1024, std::byte{0});
        std::vector<std::byte> compressed(compressor.max_compressed_size(zeros.size()));
        
        auto result = compressor.compress(zeros, compressed);
        assert(result.has_value());
        compressed.resize(*result);
        
        print_stats("All zeros (1KB)", zeros.size(), compressed.size());
        
        // Decompress and verify
        std::vector<std::byte> decompressed(zeros.size());
        auto decomp_result = compressor.decompress(compressed, decompressed);
        assert(decomp_result.has_value());
        assert(*decomp_result == zeros.size());
        assert(decompressed == zeros);
        std::cout << "✓ Zeros pattern works" << std::endl;
    }
    
    // Repeating pattern
    {
        std::vector<std::byte> pattern;
        for (int i = 0; i < 256; ++i) {
            for (int j = 0; j < 4; ++j) {
                pattern.push_back(std::byte("ABCD"[j]));
            }
        }
        
        std::vector<std::byte> compressed(compressor.max_compressed_size(pattern.size()));
        auto result = compressor.compress(pattern, compressed);
        assert(result.has_value());
        compressed.resize(*result);
        
        print_stats("ABCD pattern (1KB)", pattern.size(), compressed.size());
        
        // Decompress and verify
        std::vector<std::byte> decompressed(pattern.size());
        auto decomp_result = compressor.decompress(compressed, decompressed);
        assert(decomp_result.has_value());
        assert(decompressed == pattern);
        std::cout << "✓ Repeating pattern works" << std::endl;
    }
    
    // Random data (incompressible)
    {
        std::vector<std::byte> random_data(1024);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (auto& b : random_data) {
            b = std::byte(dis(gen));
        }
        
        std::vector<std::byte> compressed(compressor.max_compressed_size(random_data.size()));
        auto result = compressor.compress(random_data, compressed);
        assert(result.has_value());
        compressed.resize(*result);
        
        print_stats("Random data (1KB)", random_data.size(), compressed.size());
        
        // Decompress and verify
        std::vector<std::byte> decompressed(random_data.size());
        auto decomp_result = compressor.decompress(compressed, decompressed);
        assert(decomp_result.has_value());
        assert(decompressed == random_data);
        std::cout << "✓ Random data works" << std::endl;
    }
}

/**
 * @brief Test LZ4 edge cases
 */
void test_lz4_edge_cases() {
    std::cout << "\nTesting LZ4 edge cases..." << std::endl;
    
    psyfer::compression::lz4 compressor;
    
    // Empty input
    {
        std::vector<std::byte> empty;
        std::vector<std::byte> compressed(16);
        
        auto result = compressor.compress(empty, compressed);
        assert(result.has_value());
        assert(*result == 0);
        std::cout << "✓ Empty input works" << std::endl;
    }
    
    // Single byte
    {
        std::vector<std::byte> single{std::byte{42}};
        std::vector<std::byte> compressed(compressor.max_compressed_size(1));
        
        auto result = compressor.compress(single, compressed);
        assert(result.has_value());
        compressed.resize(*result);
        
        std::vector<std::byte> decompressed(1);
        auto decomp_result = compressor.decompress(compressed, decompressed);
        assert(decomp_result.has_value());
        assert(decompressed == single);
        std::cout << "✓ Single byte works" << std::endl;
    }
    
    // Very small input (< MIN_MATCH)
    {
        std::vector<std::byte> small{std::byte{1}, std::byte{2}, std::byte{3}};
        std::vector<std::byte> compressed(compressor.max_compressed_size(small.size()));
        
        auto result = compressor.compress(small, compressed);
        assert(result.has_value());
        compressed.resize(*result);
        
        std::vector<std::byte> decompressed(small.size());
        auto decomp_result = compressor.decompress(compressed, decompressed);
        assert(decomp_result.has_value());
        assert(decompressed == small);
        std::cout << "✓ Small input works" << std::endl;
    }
}

/**
 * @brief Test LZ4 frame format
 */
void test_lz4_frame() {
    std::cout << "\nTesting LZ4 frame format..." << std::endl;
    
    // Create test data with multiple blocks
    std::string test_str;
    for (int i = 0; i < 1000; ++i) {
        test_str += "The quick brown fox jumps over the lazy dog. ";
    }
    std::vector<std::byte> input;
    input.reserve(test_str.size());
    for (char c : test_str) {
        input.push_back(static_cast<std::byte>(c));
    }
    
    // Compress with frame format
    auto compressed = psyfer::compression::lz4_frame::compress_frame(input);
    assert(compressed.has_value());
    
    print_stats("Frame format", input.size(), compressed->size());
    
    // Check magic number
    assert(compressed->size() >= 4);
    uint32_t magic;
    std::memcpy(&magic, compressed->data(), 4);
    assert(magic == psyfer::compression::lz4_frame::MAGIC);
    std::cout << "✓ Magic number correct" << std::endl;
    
    // Decompress
    auto decompressed = psyfer::compression::lz4_frame::decompress_frame(*compressed);
    assert(decompressed.has_value());
    assert(*decompressed == input);
    std::cout << "✓ Frame format works" << std::endl;
}

/**
 * @brief Benchmark LZ4 performance
 */
void benchmark_lz4() {
    std::cout << "\nBenchmarking LZ4 performance..." << std::endl;
    
    psyfer::compression::lz4 compressor;
    
    // Create 1MB of semi-compressible data
    std::vector<std::byte> data;
    data.reserve(1024 * 1024);
    
    // Mix of text and binary
    std::string text = "The quick brown fox jumps over the lazy dog. ";
    for (int i = 0; i < 10000; ++i) {
        data.insert(data.end(), 
            reinterpret_cast<const std::byte*>(text.data()),
            reinterpret_cast<const std::byte*>(text.data() + text.size()));
        
        // Add some binary data
        for (int j = 0; j < 20; ++j) {
            data.push_back(std::byte(i & 0xFF));
        }
    }
    
    std::vector<std::byte> compressed(compressor.max_compressed_size(data.size()));
    
    // Compression benchmark
    auto start = std::chrono::high_resolution_clock::now();
    auto result = compressor.compress(data, compressed);
    auto end = std::chrono::high_resolution_clock::now();
    
    assert(result.has_value());
    compressed.resize(*result);
    
    auto compress_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double compress_speed = (data.size() / 1024.0 / 1024.0) / (compress_time / 1000000.0);
    
    std::cout << "Compression:" << std::endl;
    std::cout << "  Time:  " << compress_time << " μs" << std::endl;
    std::cout << "  Speed: " << std::fixed << std::setprecision(2) << compress_speed << " MB/s" << std::endl;
    
    // Decompression benchmark
    std::vector<std::byte> decompressed(data.size());
    
    start = std::chrono::high_resolution_clock::now();
    auto decomp_result = compressor.decompress(compressed, decompressed);
    end = std::chrono::high_resolution_clock::now();
    
    assert(decomp_result.has_value());
    assert(*decomp_result == data.size());
    
    auto decompress_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double decompress_speed = (data.size() / 1024.0 / 1024.0) / (decompress_time / 1000000.0);
    
    std::cout << "Decompression:" << std::endl;
    std::cout << "  Time:  " << decompress_time << " μs" << std::endl;
    std::cout << "  Speed: " << std::fixed << std::setprecision(2) << decompress_speed << " MB/s" << std::endl;
    
    print_stats("Benchmark data", data.size(), compressed.size());
}

int main() {
    std::cout << "=== LZ4 Compression Tests ===" << std::endl;
    
    test_lz4_basic();
    test_lz4_patterns();
    test_lz4_edge_cases();
    test_lz4_frame();
    benchmark_lz4();
    
    std::cout << "\n✓ All tests passed!" << std::endl;
    return 0;
}