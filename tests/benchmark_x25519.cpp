/**
 * @file benchmark_x25519.cpp
 * @brief Benchmark X25519 implementations
 */

#include <psyfer.hpp>
#include <psyfer/crypto/x25519.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>

#ifdef __x86_64__
#include <immintrin.h>
#endif

/**
 * @brief Optimized field multiplication using vector instructions
 */
class x25519_optimized {
public:
    static void scalarmult(uint8_t* out, const uint8_t* scalar, const uint8_t* point) noexcept {
        // For now, just use the base implementation
        psyfer::crypto::x25519 base;
        base.scalarmult(out, scalar, point);
    }
};

void benchmark_implementation(const std::string& name, 
                            std::function<void(uint8_t*, const uint8_t*, const uint8_t*)> impl) {
    const int iterations = 10000;
    
    // Generate test data
    std::array<uint8_t, 32> scalar;
    std::array<uint8_t, 32> point = {9}; // basepoint
    std::array<uint8_t, 32> output;
    
    // Fill scalar with random data
    for (auto& b : scalar) {
        b = static_cast<uint8_t>(rand() & 0xFF);
    }
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    
    // Warmup
    for (int i = 0; i < 100; ++i) {
        impl(output.data(), scalar.data(), point.data());
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        impl(output.data(), scalar.data(), point.data());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << std::setw(20) << name << ": "
              << std::setw(6) << duration / iterations << " μs/op, "
              << std::setw(8) << (1000000.0 * iterations) / duration << " ops/sec"
              << std::endl;
}

int main() {
    std::cout << "=== X25519 Implementation Benchmarks ===" << std::endl;
    std::cout << "Platform: " << COMPILER_NAME << " on " << PLATFORM_NAME << std::endl;
    
#ifdef __x86_64__
    std::cout << "CPU features: ";
    if (__builtin_cpu_supports("avx2")) std::cout << "AVX2 ";
    if (__builtin_cpu_supports("avx")) std::cout << "AVX ";
    if (__builtin_cpu_supports("sse4.2")) std::cout << "SSE4.2 ";
    std::cout << std::endl;
#endif
    
    std::cout << "\nBenchmarking " << 10000 << " iterations each:\n" << std::endl;
    
    // Benchmark our implementation
    benchmark_implementation("Psyfer X25519", 
        [](uint8_t* out, const uint8_t* scalar, const uint8_t* point) {
            psyfer::crypto::x25519 impl;
            impl.scalarmult(out, scalar, point);
        });
    
    // Could add more implementations here if we had them
    
    return 0;
}