# X25519 Hardware Acceleration in Psyfer

## Overview

Psyfer now supports hardware-accelerated X25519 key exchange on macOS 10.15+ and iOS 13.0+ through Apple's CryptoKit framework. When available, the implementation automatically uses CryptoKit's optimized implementation, falling back to the portable software implementation on other platforms or older macOS versions.

## Performance

Benchmarks on Apple Silicon (M-series) show significant performance improvements:

- **Key Generation**: ~2x faster (near instant due to hardware RNG)
- **Public Key Derivation**: ~12x faster (246 μs → 20 μs)
- **Shared Secret Computation**: ~12x faster (242 μs → 20 μs)
- **Overall**: ~40,000 key exchanges per second with CryptoKit vs ~4,000 with software implementation

## Implementation Details

### Swift Integration

CryptoKit is a Swift-only framework, so we created a Swift wrapper that exports C-compatible functions:

```swift
// src/crypto/x25519_cryptokit.swift
@_cdecl("x25519_cryptokit_generate_private_key")
public func x25519GeneratePrivateKey(_ privateKey: UnsafeMutablePointer<UInt8>) -> Int32
```

### Automatic Detection

The implementation automatically detects CryptoKit availability at compile time and runtime:

```cpp
#ifdef HAVE_CRYPTOKIT
    if (use_cryptokit) {
        // Use CryptoKit implementation
    }
#endif
// Fall back to software implementation
```

### Build System

The CMake build system automatically:
1. Detects Swift compiler availability
2. Creates a separate Swift static library (`psyfer_cryptokit`)
3. Links it with the main psyfer library
4. Defines `HAVE_CRYPTOKIT` when available

## Usage

No code changes are required - the existing X25519 API automatically uses hardware acceleration when available:

```cpp
// This automatically uses CryptoKit on supported platforms
auto kp = psyfer::crypto::x25519::key_pair::generate();
```

## Differences from Software Implementation

CryptoKit handles certain edge cases differently:
- Low order points produce non-zero outputs (rather than all zeros)
- Both behaviors are cryptographically safe

## Platform Support

- **macOS**: 10.15+ (Catalina and later)
- **iOS**: 13.0+
- **Other platforms**: Falls back to software implementation