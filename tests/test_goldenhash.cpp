#include <iostream>
#include <goldenhash.hpp>
#include <cstring>

int main() {
    // Create a GoldenHash with 1827 entries (same as used in LZ4)
    goldenhash::GoldenHash hasher(1827);
    
    // Test 1: Hash the same data multiple times
    uint8_t zeros[4] = {0, 0, 0, 0};
    std::cout << "Test 1: Hashing 4 zeros multiple times:" << std::endl;
    for (int i = 0; i < 5; i++) {
        uint64_t h = hasher.hash(zeros, 4);
        std::cout << "  Attempt " << i << ": hash = " << h << std::endl;
    }
    
    // Test 2: Hash from different memory locations with same data
    std::cout << "\nTest 2: Hashing zeros from different locations:" << std::endl;
    uint8_t buffer[20] = {0}; // All zeros
    for (int i = 0; i < 5; i++) {
        uint64_t h = hasher.hash(&buffer[i], 4);
        std::cout << "  Position " << i << ": hash = " << h << std::endl;
    }
    
    // Test 3: Different data should give different hashes
    std::cout << "\nTest 3: Hashing different data:" << std::endl;
    uint8_t data1[4] = {0, 0, 0, 0};
    uint8_t data2[4] = {1, 0, 0, 0};
    uint8_t data3[4] = {0, 1, 0, 0};
    uint8_t data4[4] = {1, 2, 3, 4};
    
    std::cout << "  [0,0,0,0]: hash = " << hasher.hash(data1, 4) << std::endl;
    std::cout << "  [1,0,0,0]: hash = " << hasher.hash(data2, 4) << std::endl;
    std::cout << "  [0,1,0,0]: hash = " << hasher.hash(data3, 4) << std::endl;
    std::cout << "  [1,2,3,4]: hash = " << hasher.hash(data4, 4) << std::endl;
    
    // Test 4: Check hash range
    std::cout << "\nTest 4: Checking hash range (should be 0-1826):" << std::endl;
    uint64_t min_hash = 1827, max_hash = 0;
    for (int i = 0; i < 1000; i++) {
        uint8_t test_data[4];
        test_data[0] = i & 0xFF;
        test_data[1] = (i >> 8) & 0xFF;
        test_data[2] = (i >> 16) & 0xFF;
        test_data[3] = (i >> 24) & 0xFF;
        
        uint64_t h = hasher.hash(test_data, 4);
        if (h < min_hash) min_hash = h;
        if (h > max_hash) max_hash = h;
        
        if (h >= 1827) {
            std::cerr << "ERROR: Hash value " << h << " is out of range!" << std::endl;
        }
    }
    std::cout << "  Min hash: " << min_hash << std::endl;
    std::cout << "  Max hash: " << max_hash << std::endl;
    
    return 0;
}