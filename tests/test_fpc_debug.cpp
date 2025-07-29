/**
 * @file test_fpc_debug.cpp
 * @brief Debug test for FPC compression
 */

#include <psyfer/compression/fpc.hpp>
#include <iostream>
#include <iomanip>

using namespace psyfer::compression;

void print_bytes(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), size_t(32)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 32) std::cout << "...";
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== FPC Debug Test ===" << std::endl;
    
    // Test 1: Single value
    {
        std::cout << "\nTest 1: Single value (42.0)" << std::endl;
        std::vector<double> original = {42.0};
        
        auto compressed = fpc_compress(original);
        print_bytes(compressed, "Compressed");
        
        // Manually parse the compressed data
        std::cout << "Manual parse:" << std::endl;
        std::cout << "  Compression level: " << static_cast<int>(compressed[0]) << std::endl;
        std::cout << "  Records: " << (compressed[1] | (compressed[2] << 8) | (compressed[3] << 16)) << std::endl;
        std::cout << "  Block size: " << (compressed[4] | (compressed[5] << 8) | (compressed[6] << 16)) << std::endl;
        
        // Parse header
        uint8_t header_byte = compressed[7];
        std::cout << "  Header byte: 0x" << std::hex << static_cast<int>(header_byte) << std::dec << std::endl;
        std::cout << "  Header byte binary: ";
        for (int i = 7; i >= 0; --i) {
            std::cout << ((header_byte >> i) & 1);
        }
        std::cout << std::endl;
        
        // Manual decode
        uint8_t h1_bits = (header_byte >> 4) & 0x0F;
        uint8_t h2_bits = header_byte & 0x0F;
        std::cout << "  H1 bits: " << static_cast<int>(h1_bits) << " (type=" << ((h1_bits >> 3) & 1) 
                  << " len=" << (h1_bits & 0x07) << ")" << std::endl;
        std::cout << "  H2 bits: " << static_cast<int>(h2_bits) << " (type=" << ((h2_bits >> 3) & 1) 
                  << " len=" << (h2_bits & 0x07) << ")" << std::endl;
        
        pair_header ph = pair_header::decode(header_byte);
        std::cout << "  Decoded H1: type=" << static_cast<int>(ph.h1_type) << " len=" << static_cast<int>(ph.h1_len) << std::endl;
        std::cout << "  Decoded H2: type=" << static_cast<int>(ph.h2_type) << " len=" << static_cast<int>(ph.h2_len) << std::endl;
        
        std::vector<double> decompressed(1);
        size_t count = fpc_decompress(compressed, decompressed);
        
        std::cout << "Decompressed count: " << count << std::endl;
        std::cout << "Decompressed value: " << decompressed[0] << std::endl;
        
        // Print the bits
        uint64_t orig_bits = std::bit_cast<uint64_t>(original[0]);
        uint64_t decomp_bits = std::bit_cast<uint64_t>(decompressed[0]);
        std::cout << "Original bits: 0x" << std::hex << orig_bits << std::endl;
        std::cout << "Decompressed bits: 0x" << std::hex << decomp_bits << std::dec << std::endl;
    }
    
    // Test 2: Two values
    {
        std::cout << "\nTest 2: Two values (1.0, 2.0)" << std::endl;
        std::vector<double> original = {1.0, 2.0};
        
        auto compressed = fpc_compress(original);
        print_bytes(compressed, "Compressed");
        
        std::vector<double> decompressed(2);
        size_t count = fpc_decompress(compressed, decompressed);
        
        std::cout << "Decompressed count: " << count << std::endl;
        std::cout << "Decompressed values: " << decompressed[0] << ", " << decompressed[1] << std::endl;
    }
    
    // Test 3: Simple sequence
    {
        std::cout << "\nTest 3: Simple sequence" << std::endl;
        std::vector<double> original = {1.0, 2.0, 3.0, 4.0};
        
        auto compressed = fpc_compress(original);
        print_bytes(compressed, "Compressed");
        
        std::vector<double> decompressed(4);
        size_t count = fpc_decompress(compressed, decompressed);
        
        std::cout << "Decompressed count: " << count << std::endl;
        std::cout << "Decompressed values: ";
        for (size_t i = 0; i < count; ++i) {
            std::cout << decompressed[i] << " ";
        }
        std::cout << std::endl;
    }
    
    return 0;
}