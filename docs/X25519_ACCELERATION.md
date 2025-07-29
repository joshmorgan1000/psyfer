# X25519 Hardware Acceleration Analysis

## Summary

After investigating hardware acceleration options for X25519/Curve25519, here's what I found:

### macOS/iOS
- **CryptoKit**: Swift-only API (iOS 13+/macOS 10.15+), no C/C++ interface
- **CommonCrypto**: No Curve25519 support (only AES, SHA, and NIST curves)
- **Security.framework**: No Curve25519 support (only P-256, P-384, P-521)
- **Accelerate.framework**: No Curve25519 support

### Hardware Capabilities
- **ARM64 (Apple Silicon)**: Has crypto extensions but they're designed for AES/SHA, not ECC
- **x86_64**: No dedicated Curve25519 instructions, but AVX2 can help with field arithmetic

### What libsodium does
1. **ref10**: Reference implementation (what we're using)
2. **sandy2x**: AVX-optimized implementation for x86_64 (2x parallel operations)

### Performance Comparison
- Our implementation: ~52,000 ops/sec (19 μs/op)
- This is actually quite good for a portable implementation!

### Optimization Options

1. **NEON optimization (ARM64)**
   - Can use vector instructions for field multiplication
   - Potential 20-30% speedup
   - Complex to implement correctly

2. **AVX2 optimization (x86_64)**
   - Sandy2x approach: compute 2 scalar multiplications in parallel
   - Requires significant refactoring
   - Only beneficial when batching operations

3. **Assembly optimization**
   - Hand-tuned assembly for each platform
   - Most complex but highest performance
   - libsodium's approach

### Recommendation

Our current implementation achieves good performance (52k ops/sec) without platform-specific code. Given that:

1. There's no hardware acceleration available on macOS for Curve25519
2. The performance is already competitive
3. The code is portable and maintainable

I recommend keeping the current implementation. If performance becomes critical later, we could:
- Add NEON optimizations for ARM64 (~20-30% improvement)
- Port libsodium's sandy2x for x86_64 (beneficial for batch operations)

The current implementation is secure, correct, and performant enough for most use cases.