/**
 * @file 03_compression.cpp
 * @brief Compression algorithm examples
 * 
 * This example demonstrates:
 * - LZ4 compression for general data
 * - FPC compression for floating-point data
 * - Compression ratios and performance
 * - Memory management for compression
 * - Streaming compression
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <iomanip>
#include <fstream>
#include <sstream>

// Using specific namespaces to avoid ambiguity
namespace crypto = psyfer::crypto;
namespace utils = psyfer::utils;
namespace kdf = psyfer::kdf;

/**
 * @brief Generate repetitive text data (good for compression)
 */
std::string generate_text_data() {
    std::stringstream ss;
    
    // Shakespeare quote repeated with variations
    std::vector<std::string> quotes = {
        "To be, or not to be, that is the question. ",
        "Whether 'tis nobler in the mind to suffer ",
        "The slings and arrows of outrageous fortune, ",
        "Or to take arms against a sea of troubles. "
    };
    
    // Generate repetitive pattern
    for (int i = 0; i < 100; ++i) {
        ss << quotes[i % quotes.size()];
        if (i % 10 == 0) ss << "\n";
    }
    
    return ss.str();
}

/**
 * @brief Generate random binary data (poor compression)
 */
std::vector<std::byte> generate_random_data(size_t size) {
    std::vector<std::byte> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (auto& byte : data) {
        byte = static_cast<std::byte>(dis(gen));
    }
    
    return data;
}

/**
 * @brief Example 1: Basic LZ4 compression
 */
void example_lz4_basic() {
    std::cout << "\n=== Example 1: Basic LZ4 Compression ===\n";
    
    crypto::lz4 compressor;
    
    // Test 1: Compress text data
    {
        std::string text = generate_text_data();
        std::vector<std::byte> input(
            reinterpret_cast<const std::byte*>(text.data()),
            reinterpret_cast<const std::byte*>(text.data() + text.size())
        );
        
        // Allocate output buffer
        std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
        
        // Compress
        auto result = compressor.compress(input, compressed);
        if (!result) {
            std::cerr << "Compression failed: " << result.error().message() << "\n";
            return;
        }
        
        size_t compressed_size = result.value();
        compressed.resize(compressed_size);
        
        double ratio = double(input.size()) / compressed_size;
        
        std::cout << "Text compression:\n";
        std::cout << "  Original size:    " << input.size() << " bytes\n";
        std::cout << "  Compressed size:  " << compressed_size << " bytes\n";
        std::cout << "  Compression ratio: " << std::fixed << std::setprecision(2) 
                  << ratio << ":1 (" << (100.0 * compressed_size / input.size()) << "%)\n";
        
        // Decompress to verify
        std::vector<std::byte> decompressed(input.size());
        auto decomp_result = compressor.decompress(compressed, decompressed);
        if (!decomp_result) {
            std::cerr << "Decompression failed\n";
            return;
        }
        
        bool matches = (decompressed == input);
        std::cout << "  Decompression: " << (matches ? "✅ SUCCESS" : "❌ FAILED") << "\n";
    }
    
    // Test 2: Compress random data (worst case)
    {
        std::cout << "\nRandom data compression:\n";
        auto random_data = generate_random_data(1000);
        
        std::vector<std::byte> compressed(compressor.max_compressed_size(random_data.size()));
        auto result = compressor.compress(random_data, compressed);
        
        if (result) {
            size_t compressed_size = result.value();
            double ratio = double(random_data.size()) / compressed_size;
            
            std::cout << "  Original size:    " << random_data.size() << " bytes\n";
            std::cout << "  Compressed size:  " << compressed_size << " bytes\n";
            std::cout << "  Compression ratio: " << std::fixed << std::setprecision(2) 
                      << ratio << ":1\n";
        }
    }
}

/**
 * @brief Example 2: FPC compression for floating-point data
 */
void example_fpc_compression() {
    std::cout << "\n=== Example 2: FPC Floating-Point Compression ===\n";
    
    // Generate different types of floating-point data
    
    // Smooth sensor data (compresses well)
    {
        std::cout << "Smooth sensor data:\n";
        std::vector<double> sensor_data;
        double value = 20.0;
        
        for (int i = 0; i < 1000; ++i) {
            value += 0.1 * std::sin(i * 0.1);
            sensor_data.push_back(value);
        }
        
        auto compressed = crypto::fpc_compress(sensor_data);
        double ratio = (sensor_data.size() * sizeof(double)) / double(compressed.size());
        
        std::cout << "  Original size:    " << sensor_data.size() * sizeof(double) << " bytes\n";
        std::cout << "  Compressed size:  " << compressed.size() << " bytes\n";
        std::cout << "  Compression ratio: " << std::fixed << std::setprecision(2) 
                  << ratio << ":1\n";
        
        // Decompress
        std::vector<double> decompressed(sensor_data.size());
        size_t count = crypto::fpc_decompress(compressed, decompressed);
        
        std::cout << "  Decompressed: " << count << " values\n";
        
        // Check accuracy
        double max_error = 0.0;
        for (size_t i = 0; i < sensor_data.size() && i < count; ++i) {
            double error = std::abs(sensor_data[i] - decompressed[i]);
            max_error = std::max(max_error, error);
        }
        std::cout << "  Max error: " << std::scientific << max_error << "\n";
    }
    
    // Financial data (high precision required)
    {
        std::cout << "\nFinancial data (prices):\n";
        std::vector<double> prices;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::normal_distribution<> price_dist(100.0, 0.5);
        
        for (int i = 0; i < 500; ++i) {
            prices.push_back(std::round(price_dist(gen) * 100) / 100); // 2 decimal places
        }
        
        auto compressed = crypto::fpc_compress(prices);
        double ratio = (prices.size() * sizeof(double)) / double(compressed.size());
        
        std::cout << "  Original size:    " << prices.size() * sizeof(double) << " bytes\n";
        std::cout << "  Compressed size:  " << compressed.size() << " bytes\n";
        std::cout << "  Compression ratio: " << std::fixed << std::setprecision(2) 
                  << ratio << ":1\n";
    }
    
    // Different compression levels
    {
        std::cout << "\nCompression level comparison:\n";
        std::vector<double> data(1000, 3.14159265359);
        
        for (auto level : {crypto::fpc_compression_level::MIN,
                          crypto::fpc_compression_level::DEFAULT,
                          crypto::fpc_compression_level::MAX}) {
            auto compressed = crypto::fpc_compress(data, level);
            std::cout << "  Level " << static_cast<int>(level) << ": " 
                      << compressed.size() << " bytes\n";
        }
    }
}

/**
 * @brief Example 3: LZ4 high compression mode
 */
void example_lz4_high_compression() {
    std::cout << "\n=== Example 3: LZ4 High Compression Mode ===\n";
    
    crypto::lz4 compressor;
    
    // Generate JSON-like data (highly compressible)
    std::stringstream json;
    json << "[\n";
    for (int i = 0; i < 100; ++i) {
        json << "  {\n";
        json << "    \"id\": " << i << ",\n";
        json << "    \"name\": \"User " << i << "\",\n";
        json << "    \"email\": \"user" << i << "@example.com\",\n";
        json << "    \"status\": \"active\",\n";
        json << "    \"created\": \"2024-01-01T00:00:00Z\",\n";
        json << "    \"type\": \"standard\"\n";
        json << "  }" << (i < 99 ? "," : "") << "\n";
    }
    json << "]\n";
    
    std::string json_str = json.str();
    std::vector<std::byte> input(
        reinterpret_cast<const std::byte*>(json_str.data()),
        reinterpret_cast<const std::byte*>(json_str.data() + json_str.size())
    );
    
    // Standard compression
    std::vector<std::byte> compressed_standard(compressor.max_compressed_size(input.size()));
    auto result1 = compressor.compress(input, compressed_standard);
    
    // High compression mode
    std::vector<std::byte> compressed_hc(compressor.max_compressed_size(input.size()));
    auto result2 = compressor.compress_hc(input, compressed_hc);
    
    if (result1 && result2) {
        std::cout << "JSON data compression:\n";
        std::cout << "  Original size:        " << input.size() << " bytes\n";
        std::cout << "  Standard compression: " << result1.value() << " bytes ("
                  << std::fixed << std::setprecision(1) 
                  << (100.0 * result1.value() / input.size()) << "%)\n";
        std::cout << "  High compression:     " << result2.value() << " bytes ("
                  << (100.0 * result2.value() / input.size()) << "%)\n";
        std::cout << "  Extra savings:        " 
                  << (result1.value() - result2.value()) << " bytes\n";
    }
}

/**
 * @brief Example 4: Streaming compression
 */
void example_streaming_compression() {
    std::cout << "\n=== Example 4: Streaming Compression ===\n";
    
    // Simulate compressing a large file in chunks
    crypto::lz4 compressor;
    
    // Create test data
    std::string line = "This is a line of log data that will be repeated many times.\n";
    const size_t total_lines = 1000;
    const size_t chunk_lines = 100;
    
    std::vector<std::vector<std::byte>> compressed_chunks;
    size_t total_input = 0;
    size_t total_output = 0;
    
    std::cout << "Compressing " << total_lines << " lines in chunks of " 
              << chunk_lines << " lines...\n";
    
    // Compress in chunks
    for (size_t i = 0; i < total_lines; i += chunk_lines) {
        // Build chunk
        std::stringstream chunk;
        for (size_t j = 0; j < chunk_lines && i + j < total_lines; ++j) {
            chunk << "[" << (i + j) << "] " << line;
        }
        
        std::string chunk_str = chunk.str();
        std::vector<std::byte> input(
            reinterpret_cast<const std::byte*>(chunk_str.data()),
            reinterpret_cast<const std::byte*>(chunk_str.data() + chunk_str.size())
        );
        
        // Compress chunk
        std::vector<std::byte> compressed(compressor.max_compressed_size(input.size()));
        auto result = compressor.compress(input, compressed);
        
        if (result) {
            compressed.resize(result.value());
            compressed_chunks.push_back(compressed);
            total_input += input.size();
            total_output += result.value();
        }
    }
    
    std::cout << "Compression complete:\n";
    std::cout << "  Chunks:           " << compressed_chunks.size() << "\n";
    std::cout << "  Total input:      " << total_input << " bytes\n";
    std::cout << "  Total compressed: " << total_output << " bytes\n";
    std::cout << "  Overall ratio:    " << std::fixed << std::setprecision(2)
              << (double(total_input) / total_output) << ":1\n";
    
    // Decompress and verify
    std::cout << "\nDecompressing chunks...\n";
    size_t decompressed_size = 0;
    
    for (const auto& compressed : compressed_chunks) {
        // In real use, you'd need to know the decompressed size
        std::vector<std::byte> decompressed(line.size() * chunk_lines * 2);
        auto result = compressor.decompress(compressed, decompressed);
        
        if (result) {
            decompressed_size += result.value();
        }
    }
    
    std::cout << "Total decompressed: " << decompressed_size << " bytes\n";
    std::cout << "Matches original: " << (decompressed_size == total_input ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 5: Performance benchmarks
 */
void example_performance() {
    std::cout << "\n=== Example 5: Compression Performance ===\n";
    
    const size_t data_size = 1'000'000; // 1 MB
    const int iterations = 10;
    
    // Generate test data with varying compressibility
    std::vector<std::byte> highly_compressible(data_size);
    std::vector<std::byte> medium_compressible(data_size);
    std::vector<std::byte> poorly_compressible(data_size);
    
    // Highly compressible: repeated pattern
    for (size_t i = 0; i < data_size; ++i) {
        highly_compressible[i] = static_cast<std::byte>(i % 10);
    }
    
    // Medium compressible: text-like
    std::string text = "The quick brown fox jumps over the lazy dog. ";
    for (size_t i = 0; i < data_size; ++i) {
        medium_compressible[i] = static_cast<std::byte>(text[i % text.size()]);
    }
    
    // Poorly compressible: random
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : poorly_compressible) {
        byte = static_cast<std::byte>(dis(gen));
    }
    
    crypto::lz4 compressor;
    
    // Benchmark function
    auto benchmark = [&](const std::string& name, const std::vector<std::byte>& data) {
        std::vector<std::byte> compressed(compressor.max_compressed_size(data.size()));
        
        // Compression benchmark
        auto start = std::chrono::high_resolution_clock::now();
        size_t compressed_size = 0;
        
        for (int i = 0; i < iterations; ++i) {
            auto result = compressor.compress(data, compressed);
            if (result) compressed_size = result.value();
        }
        
        auto comp_time = std::chrono::high_resolution_clock::now() - start;
        
        // Decompression benchmark
        compressed.resize(compressed_size);
        std::vector<std::byte> decompressed(data.size());
        
        start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; ++i) {
            compressor.decompress(compressed, decompressed);
        }
        
        auto decomp_time = std::chrono::high_resolution_clock::now() - start;
        
        // Calculate throughput
        double comp_throughput = (data.size() * iterations) / 
            (std::chrono::duration<double>(comp_time).count() * 1e6);
        double decomp_throughput = (data.size() * iterations) / 
            (std::chrono::duration<double>(decomp_time).count() * 1e6);
        
        std::cout << name << ":\n";
        std::cout << "  Compression ratio:   " << std::fixed << std::setprecision(2)
                  << (double(data.size()) / compressed_size) << ":1\n";
        std::cout << "  Compression speed:   " << std::fixed << std::setprecision(1)
                  << comp_throughput << " MB/s\n";
        std::cout << "  Decompression speed: " << decomp_throughput << " MB/s\n";
    };
    
    benchmark("Highly compressible", highly_compressible);
    benchmark("Medium compressible", medium_compressible);
    benchmark("Poorly compressible", poorly_compressible);
}

/**
 * @brief Example 6: Multi-dimensional array compression with FPC
 */
void example_multidimensional_fpc() {
    std::cout << "\n=== Example 6: Multi-dimensional Array Compression ===\n";
    
    // Create a 2D temperature grid (e.g., weather simulation)
    const size_t rows = 100;
    const size_t cols = 100;
    std::vector<double> temperature_grid;
    temperature_grid.reserve(rows * cols);
    
    // Generate smooth 2D data
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            double x = i / double(rows) * 10;
            double y = j / double(cols) * 10;
            double temp = 20.0 + 5.0 * std::sin(x) * std::cos(y);
            temperature_grid.push_back(temp);
        }
    }
    
    std::cout << "2D Temperature Grid (" << rows << "x" << cols << "):\n";
    
    // Compress using FPC
    auto compressed = crypto::fpc_compress_2d(
        std::span<const double>(temperature_grid), rows, cols, 
        crypto::fpc_compression_level::DEFAULT
    );
    
    size_t original_size = temperature_grid.size() * sizeof(double);
    double ratio = double(original_size) / compressed.size();
    
    std::cout << "  Original size:    " << original_size << " bytes\n";
    std::cout << "  Compressed size:  " << compressed.size() << " bytes\n";
    std::cout << "  Compression ratio: " << std::fixed << std::setprecision(2) 
              << ratio << ":1\n";
    
    // Compress with tensor metadata
    std::vector<size_t> dims = {rows, cols};
    auto tensor_compressed = crypto::fpc_compress_tensor(std::span<const double>(temperature_grid), dims);
    
    std::cout << "\nWith tensor metadata:\n";
    std::cout << "  Compressed size:  " << tensor_compressed.size() << " bytes\n";
    std::cout << "  Overhead:         " << (tensor_compressed.size() - compressed.size()) 
              << " bytes\n";
    
    // Decompress and verify
    auto decompressed_result = crypto::fpc_decompress_tensor<double>(tensor_compressed);
    if (decompressed_result) {
        auto& [data, recovered_dims] = *decompressed_result;
        std::cout << "  Decompressed successfully\n";
        std::cout << "  Dimensions:       " << recovered_dims[0] << "x" << recovered_dims[1] << "\n";
        
        // Check data integrity
        double max_error = 0.0;
        for (size_t i = 0; i < temperature_grid.size() && i < data.size(); ++i) {
            max_error = std::max(max_error, std::abs(temperature_grid[i] - data[i]));
        }
        std::cout << "  Max error:        " << std::scientific << max_error << "\n";
    }
}

int main() {
    std::cout << "Psyfer Compression Examples\n";
    std::cout << "==========================\n";
    
    try {
        example_lz4_basic();
        example_fpc_compression();
        example_lz4_high_compression();
        example_streaming_compression();
        example_performance();
        example_multidimensional_fpc();
        
        std::cout << "\n✅ All compression examples completed successfully!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}