/**
 * @file test_x25519_cryptokit.cpp
 * @brief Test X25519 CryptoKit acceleration
 */

#include <psyfer.hpp>
#include <psyfer/crypto/x25519.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <functional>

#ifdef HAVE_CRYPTOKIT
extern "C" {
#include "../src/crypto/x25519_cryptokit.h"
}
#endif

void benchmark_implementation(const std::string& name, 
                            std::function<void()> impl,
                            int iterations = 10000) {
    // Warmup
    for (int i = 0; i < 100; ++i) {
        impl();
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        impl();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << std::setw(25) << name << ": "
              << std::setw(6) << duration / iterations << " μs/op, "
              << std::setw(8) << std::fixed << std::setprecision(1) 
              << (1000000.0 * iterations) / duration << " ops/sec"
              << std::endl;
}

int main() {
    std::cout << "=== X25519 CryptoKit vs Software Benchmark ===" << std::endl;
    
#ifdef HAVE_CRYPTOKIT
    if (x25519_cryptokit_available()) {
        std::cout << "CryptoKit is available!" << std::endl;
    } else {
        std::cout << "CryptoKit is NOT available (requires macOS 10.15+)" << std::endl;
    }
#else
    std::cout << "CryptoKit support not compiled in" << std::endl;
#endif
    
    std::cout << "\nBenchmarking scalar multiplication operations:\n" << std::endl;
    
    // Test data
    std::array<std::byte, 32> private_key;
    std::array<std::byte, 32> public_key;
    std::array<std::byte, 32> peer_public_key;
    std::array<std::byte, 32> shared_secret;
    
    // Initialize with test data
    psyfer::crypto::x25519::generate_private_key(private_key);
    psyfer::crypto::x25519::derive_public_key(private_key, peer_public_key);
    
    // Benchmark key generation
    std::cout << "Key Generation:" << std::endl;
    
    benchmark_implementation("Psyfer (auto-detect)", [&]() {
        psyfer::crypto::x25519::generate_private_key(private_key);
    });
    
#ifdef HAVE_CRYPTOKIT
    if (x25519_cryptokit_available()) {
        benchmark_implementation("CryptoKit (direct)", [&]() {
            x25519_cryptokit_generate_private_key(
                reinterpret_cast<uint8_t*>(private_key.data()));
        });
    }
#endif
    
    // Benchmark public key derivation
    std::cout << "\nPublic Key Derivation:" << std::endl;
    
    benchmark_implementation("Psyfer (auto-detect)", [&]() {
        psyfer::crypto::x25519::derive_public_key(private_key, public_key);
    });
    
#ifdef HAVE_CRYPTOKIT
    if (x25519_cryptokit_available()) {
        benchmark_implementation("CryptoKit (direct)", [&]() {
            x25519_cryptokit_derive_public_key(
                reinterpret_cast<const uint8_t*>(private_key.data()),
                reinterpret_cast<uint8_t*>(public_key.data()));
        });
    }
#endif
    
    // Benchmark shared secret computation
    std::cout << "\nShared Secret Computation:" << std::endl;
    
    benchmark_implementation("Psyfer (auto-detect)", [&]() {
        psyfer::crypto::x25519::compute_shared_secret(
            private_key, peer_public_key, shared_secret);
    });
    
#ifdef HAVE_CRYPTOKIT
    if (x25519_cryptokit_available()) {
        benchmark_implementation("CryptoKit (direct)", [&]() {
            x25519_cryptokit_compute_shared_secret(
                reinterpret_cast<const uint8_t*>(private_key.data()),
                reinterpret_cast<const uint8_t*>(peer_public_key.data()),
                reinterpret_cast<uint8_t*>(shared_secret.data()));
        });
    }
#endif
    
    // Force software implementation for comparison
    std::cout << "\nForcing software implementation:" << std::endl;
    
    benchmark_implementation("Software (Montgomery)", [&]() {
        // Call the static scalarmult directly
        uint8_t out[32];
        psyfer::crypto::x25519 impl;
        impl.scalarmult(out, 
            reinterpret_cast<const uint8_t*>(private_key.data()),
            reinterpret_cast<const uint8_t*>(peer_public_key.data()));
    });
    
    return 0;
}