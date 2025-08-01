#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <iomanip>

int main() {
    std::cout << "=== LZ4 Debug Test ===" << std::endl;
    
    psyfer::lz4 compressor;
    
    // Create a small test case with zeros
    std::vector<std::byte> zeros(50, std::byte{0});
    
    std::cout << "\nInput: 50 zeros" << std::endl;
    
    // Compress
    std::vector<std::byte> compressed(compressor.max_compressed_size(zeros.size()));
    auto result = compressor.compress(zeros, compressed);
    
    if (!result) {
        std::cerr << "Compression failed: " << result.error().message() << std::endl;
        return 1;
    }
    
    size_t compressed_size = *result;
    std::cout << "Compressed size: " << compressed_size << " bytes" << std::endl;
    std::cout << "Compression ratio: " << (100.0 * compressed_size / zeros.size()) << "%" << std::endl;
    
    // Print compressed data in hex
    std::cout << "\nCompressed data (hex):" << std::endl;
    for (size_t i = 0; i < compressed_size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(static_cast<uint8_t>(compressed[i])) << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
    
    // Analyze the compressed data
    std::cout << "\nAnalysis:" << std::endl;
    
    // First byte should be a token
    uint8_t token = static_cast<uint8_t>(compressed[0]);
    size_t literal_length = token >> 4;
    size_t match_length = token & 0x0F;
    
    std::cout << "First token: 0x" << std::hex << (int)token << std::dec << std::endl;
    std::cout << "  Literal length in token: " << literal_length << std::endl;
    std::cout << "  Match length in token: " << match_length << std::endl;
    
    // For 50 zeros, we expect:
    // - Some initial literals
    // - Then matches referring back to the beginning
    
    return 0;
}