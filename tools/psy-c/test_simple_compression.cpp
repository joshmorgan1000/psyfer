/**
 * @file test_simple_compression.cpp
 * @brief Simple test to debug compression issue
 */

#include <iostream>
#include <psyfer.hpp>

int main() {
    // Create some test data
    std::string test_data = "Hello, world! This is a test of LZ4 compression. "
                           "Repeated text repeated text repeated text repeated text.";
    
    auto input = std::as_bytes(std::span(test_data));
    
    std::cout << "Input size: " << input.size() << " bytes\n";
    std::cout << "Input: \"" << test_data << "\"\n\n";
    
    // Try to compress
    psyfer::compression::lz4 compressor;
    size_t max_size = compressor.max_compressed_size(input.size());
    std::cout << "Max compressed size: " << max_size << " bytes\n";
    
    std::vector<std::byte> compressed(max_size);
    auto result = compressor.compress(input, compressed);
    
    if (!result) {
        std::cerr << "Compression failed: " << result.error().message() << "\n";
        std::cerr << "Error code: " << static_cast<int>(result.error().value()) << "\n";
        return 1;
    }
    
    std::cout << "Compressed size: " << *result << " bytes\n";
    std::cout << "Compression ratio: " << (100.0 - (*result * 100.0 / input.size())) << "%\n";
    
    // Try to decompress
    psyfer::compression::lz4 decompressor;
    std::vector<std::byte> decompressed(input.size() * 2);
    auto decomp_result = decompressor.decompress(
        std::span(compressed.data(), *result),
        decompressed
    );
    
    if (!decomp_result) {
        std::cerr << "Decompression failed: " << decomp_result.error().message() << "\n";
        return 1;
    }
    
    std::cout << "\nDecompressed size: " << *decomp_result << " bytes\n";
    
    // Compare
    if (*decomp_result == input.size()) {
        std::string_view decompressed_str(
            reinterpret_cast<const char*>(decompressed.data()),
            *decomp_result
        );
        std::cout << "Decompressed: \"" << decompressed_str << "\"\n";
        std::cout << "Match: " << (decompressed_str == test_data ? "YES" : "NO") << "\n";
    }
    
    return 0;
}