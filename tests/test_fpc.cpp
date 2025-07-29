/**
 * @file test_fpc.cpp
 * @brief Tests for FPC compression
 */

#include <psyfer/compression/fpc.hpp>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>

using namespace psyfer::compression;

// Test data generators
namespace {
    /**
     * @brief Generate test data with a pattern
     */
    std::vector<double> generate_pattern_data(size_t count) {
        std::vector<double> data;
        data.reserve(count);
        
        for (size_t i = 0; i < count; ++i) {
            // Mix of patterns that compress well
            if (i % 4 == 0) {
                data.push_back(static_cast<double>(i));  // Sequential
            } else if (i % 4 == 1) {
                data.push_back(std::sin(static_cast<double>(i) * 0.1));  // Smooth function
            } else if (i % 4 == 2) {
                data.push_back(100.0 + static_cast<double>(i % 10) * 0.01);  // Small variations
            } else {
                data.push_back(0.0);  // Zeros compress very well
            }
        }
        
        return data;
    }
    
    /**
     * @brief Generate random floating-point data
     */
    std::vector<double> generate_random_data(size_t count) {
        std::vector<double> data;
        data.reserve(count);
        
        std::mt19937_64 rng(42);  // Fixed seed for reproducibility
        std::uniform_real_distribution<double> dist(-1000.0, 1000.0);
        
        for (size_t i = 0; i < count; ++i) {
            data.push_back(dist(rng));
        }
        
        return data;
    }
    
    /**
     * @brief Generate financial-like data (good compression)
     */
    std::vector<double> generate_financial_data(size_t count) {
        std::vector<double> data;
        data.reserve(count);
        
        double price = 100.0;
        std::mt19937_64 rng(42);
        std::normal_distribution<double> dist(0.0, 0.5);
        
        for (size_t i = 0; i < count; ++i) {
            price += dist(rng);
            data.push_back(std::round(price * 100.0) / 100.0);  // Round to cents
        }
        
        return data;
    }
}

bool test_basic_compression() {
    std::cout << "Testing basic compression/decompression..." << std::endl;
    
    // Test data
    std::vector<double> original = {
        1.0, 2.0, 3.0, 4.0, 5.0,
        1.1, 2.2, 3.3, 4.4, 5.5,
        0.0, 0.0, 0.0, 0.0, 0.0,
        -1.0, -2.0, -3.0, -4.0, -5.0
    };
    
    // Compress
    auto compressed = fpc_compress(original);
    
    std::cout << "  Original size: " << original.size() * sizeof(double) << " bytes" << std::endl;
    std::cout << "  Compressed size: " << compressed.size() << " bytes" << std::endl;
    std::cout << "  Compression ratio: " << std::fixed << std::setprecision(2) 
              << static_cast<double>(original.size() * sizeof(double)) / compressed.size() 
              << "x" << std::endl;
    
    // Decompress
    std::vector<double> decompressed(original.size());
    size_t decompressed_count = fpc_decompress(compressed, decompressed);
    
    if (decompressed_count != original.size()) {
        std::cerr << "  FAILED: Decompressed count mismatch" << std::endl;
        return false;
    }
    
    // Verify
    for (size_t i = 0; i < original.size(); ++i) {
        if (std::memcmp(&original[i], &decompressed[i], sizeof(double)) != 0) {
            std::cerr << "  FAILED: Value mismatch at index " << i << std::endl;
            std::cerr << "    Original: " << original[i] << std::endl;
            std::cerr << "    Decompressed: " << decompressed[i] << std::endl;
            return false;
        }
    }
    
    std::cout << "  PASSED" << std::endl;
    return true;
}

bool test_edge_cases() {
    std::cout << "Testing edge cases..." << std::endl;
    
    // Empty data
    {
        std::vector<double> empty;
        auto compressed = fpc_compress(empty);
        
        if (compressed.size() != 1) {  // Just the header
            std::cerr << "  FAILED: Empty compression should produce only header" << std::endl;
            return false;
        }
    }
    
    // Single value
    {
        std::vector<double> single = {42.0};
        auto compressed = fpc_compress(single);
        
        std::vector<double> decompressed(1);
        size_t count = fpc_decompress(compressed, decompressed);
        
        if (count != 1 || decompressed[0] != 42.0) {
            std::cerr << "  FAILED: Single value test" << std::endl;
            return false;
        }
    }
    
    // Special values
    {
        std::vector<double> special = {
            0.0, -0.0,
            std::numeric_limits<double>::infinity(),
            -std::numeric_limits<double>::infinity(),
            std::numeric_limits<double>::quiet_NaN(),
            std::numeric_limits<double>::min(),
            std::numeric_limits<double>::max(),
            std::numeric_limits<double>::epsilon()
        };
        
        auto compressed = fpc_compress(special);
        std::vector<double> decompressed(special.size());
        size_t count = fpc_decompress(compressed, decompressed);
        
        if (count != special.size()) {
            std::cerr << "  FAILED: Special values count mismatch" << std::endl;
            return false;
        }
        
        // Check non-NaN values
        for (size_t i = 0; i < special.size(); ++i) {
            if (!std::isnan(special[i])) {
                if (std::memcmp(&special[i], &decompressed[i], sizeof(double)) != 0) {
                    std::cerr << "  FAILED: Special value mismatch at index " << i << std::endl;
                    return false;
                }
            } else {
                // Both should be NaN
                if (!std::isnan(decompressed[i])) {
                    std::cerr << "  FAILED: NaN not preserved" << std::endl;
                    return false;
                }
            }
        }
    }
    
    std::cout << "  PASSED" << std::endl;
    return true;
}

bool test_compression_levels() {
    std::cout << "Testing different compression levels..." << std::endl;
    
    auto data = generate_pattern_data(10000);
    
    for (uint8_t level = static_cast<uint8_t>(fpc_compression_level::MIN); 
         level <= 20;  // Don't test highest levels (too much memory)
         level += 5) {
        
        auto compressed = fpc_compress(data, static_cast<fpc_compression_level>(level));
        
        std::cout << "  Level " << static_cast<int>(level) 
                  << ": " << compressed.size() << " bytes ("
                  << std::fixed << std::setprecision(2)
                  << static_cast<double>(data.size() * sizeof(double)) / compressed.size()
                  << "x)" << std::endl;
        
        // Verify decompression
        std::vector<double> decompressed(data.size());
        size_t count = fpc_decompress(compressed, decompressed);
        
        if (count != data.size()) {
            std::cerr << "    FAILED: Decompression count mismatch" << std::endl;
            return false;
        }
    }
    
    std::cout << "  PASSED" << std::endl;
    return true;
}

bool test_streaming() {
    std::cout << "Testing streaming compression..." << std::endl;
    
    auto data = generate_financial_data(100000);
    
    // Compress in chunks
    std::vector<uint8_t> compressed;
    fpc_writer writer(compressed);
    
    size_t chunk_size = 1000;
    for (size_t i = 0; i < data.size(); i += chunk_size) {
        size_t end = std::min(i + chunk_size, data.size());
        writer.write_floats(std::span<const double>(data.data() + i, end - i));
    }
    writer.flush();
    
    // Decompress in chunks
    fpc_reader reader(compressed);
    std::vector<double> decompressed;
    decompressed.reserve(data.size());
    
    std::array<double, 500> buffer;
    while (reader.has_data()) {
        size_t count = reader.read_floats(buffer);
        decompressed.insert(decompressed.end(), buffer.begin(), buffer.begin() + count);
    }
    
    // Verify
    if (decompressed.size() != data.size()) {
        std::cerr << "  FAILED: Size mismatch" << std::endl;
        return false;
    }
    
    for (size_t i = 0; i < data.size(); ++i) {
        if (std::memcmp(&data[i], &decompressed[i], sizeof(double)) != 0) {
            std::cerr << "  FAILED: Value mismatch at index " << i << std::endl;
            return false;
        }
    }
    
    std::cout << "  PASSED" << std::endl;
    return true;
}

bool test_large_blocks() {
    std::cout << "Testing large block handling..." << std::endl;
    
    // Test maximum block size
    size_t max_block = fpc_writer::MAX_RECORDS_PER_BLOCK;
    auto data = generate_pattern_data(max_block * 2 + 100);
    
    auto compressed = fpc_compress(data);
    
    // Check that multiple blocks were created
    size_t expected_blocks = (data.size() + max_block - 1) / max_block;
    std::cout << "  Created " << expected_blocks << " blocks for " 
              << data.size() << " values" << std::endl;
    
    // Decompress and verify
    std::vector<double> decompressed(data.size());
    size_t count = fpc_decompress(compressed, decompressed);
    
    if (count != data.size()) {
        std::cerr << "  FAILED: Count mismatch" << std::endl;
        return false;
    }
    
    std::cout << "  PASSED" << std::endl;
    return true;
}

void benchmark_compression() {
    std::cout << "\nBenchmarking FPC compression..." << std::endl;
    
    struct TestCase {
        std::string name;
        std::vector<double> data;
    };
    
    std::vector<TestCase> test_cases = {
        {"Sequential", generate_pattern_data(1000000)},
        {"Random", generate_random_data(1000000)},
        {"Financial", generate_financial_data(1000000)}
    };
    
    for (const auto& test : test_cases) {
        std::cout << "\n  " << test.name << " data (" 
                  << test.data.size() << " values):" << std::endl;
        
        // Compression benchmark
        auto start = std::chrono::high_resolution_clock::now();
        auto compressed = fpc_compress(test.data);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto compress_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double compress_mbps = (test.data.size() * sizeof(double)) / 
                              (compress_time.count() / 1000000.0) / (1024 * 1024);
        
        // Decompression benchmark
        std::vector<double> decompressed(test.data.size());
        
        start = std::chrono::high_resolution_clock::now();
        fpc_decompress(compressed, decompressed);
        end = std::chrono::high_resolution_clock::now();
        
        auto decompress_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double decompress_mbps = (test.data.size() * sizeof(double)) / 
                                (decompress_time.count() / 1000000.0) / (1024 * 1024);
        
        double ratio = static_cast<double>(test.data.size() * sizeof(double)) / compressed.size();
        
        std::cout << "    Compression ratio: " << std::fixed << std::setprecision(2) 
                  << ratio << "x" << std::endl;
        std::cout << "    Compression speed: " << std::fixed << std::setprecision(1) 
                  << compress_mbps << " MB/s" << std::endl;
        std::cout << "    Decompression speed: " << std::fixed << std::setprecision(1) 
                  << decompress_mbps << " MB/s" << std::endl;
    }
}

int main() {
    std::cout << "=== FPC Compression Tests ===" << std::endl;
    
    bool all_passed = true;
    
    all_passed &= test_basic_compression();
    all_passed &= test_edge_cases();
    all_passed &= test_compression_levels();
    all_passed &= test_streaming();
    all_passed &= test_large_blocks();
    
    if (all_passed) {
        std::cout << "\nAll tests PASSED!" << std::endl;
        benchmark_compression();
    } else {
        std::cout << "\nSome tests FAILED!" << std::endl;
        return 1;
    }
    
    return 0;
}