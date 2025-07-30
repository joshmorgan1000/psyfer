# Contributing to Psyfer

Thank you for your interest in contributing to Psyfer! We welcome contributions from the community and are grateful for any help you can provide.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Accept feedback gracefully
- Put the project's best interests first

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/joshmorgan1000/psyfer.git
   cd psyfer
   ```
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/joshmorgan1000/psyfer.git
   ```
4. Create a new branch for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- C++23 compatible compiler (GCC 12+, Clang 15+, MSVC 2022+)
- CMake 3.20+
- Ninja build system
- OpenSSL 3.0+
- Python 3.8+ (for code generation tools)

### Building

```bash
./run_builder.sh --debug

# Or manually:
mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug ..
ninja
```

### Running Tests

```bash
# Run all tests
./run_builder.sh --test --all

# Run specific test
./run_builder.sh --test test_aes_comprehensive
```

## Contribution Guidelines

### Code Style

- Follow the existing code style in the project
- Use modern C++ features (C++23)
- Prefer `std::span` and `std::array` over raw pointers
- Use RAII for resource management
- Document all public APIs with Doxygen comments in Javadoc style

Example:
```cpp
/**
 * @brief Encrypts data in-place using AES-256-GCM
 * @param data Data to encrypt (modified in-place)
 * @param key 256-bit encryption key
 * @param nonce 96-bit nonce (must be unique per key)
 * @param tag Output parameter for 128-bit authentication tag
 * @return Error code or success
 */
[[nodiscard]] std::error_code encrypt(
    std::span<std::byte> data,
    std::span<const std::byte, 32> key,
    std::span<const std::byte, 12> nonce,
    std::span<std::byte, 16> tag
) noexcept;
```

### Platform-Specific Code

Use preprocessor directives for platform-specific implementations:

```cpp
#ifdef __linux__
    // Linux-specific code
#elif defined(__APPLE__)
    // macOS-specific code
#elif defined(_WIN32)
    // Windows-specific code
#endif
```

### Security Considerations

- Never log or expose sensitive data (keys, passwords, etc.)
- Always use secure random number generation
- Implement constant-time operations for cryptographic code
- Zero sensitive memory before deallocation
- Follow cryptographic best practices

### Testing

- Write comprehensive unit tests for new features
- Ensure all tests pass on all supported platforms
- Add test vectors for cryptographic implementations
- Test edge cases and error conditions
- Aim for high code coverage

### Documentation

- Update README.md if adding new features
- Document all public APIs with Doxygen
- Provide usage examples for new features
- Update CHANGELOG.md with your changes

## Submitting Changes

### Pull Request Process

1. Ensure your code follows the style guidelines
2. Add tests for your changes
3. Run all tests locally to ensure they pass
4. Update documentation as needed
5. Commit your changes with a clear message:
   ```bash
   git commit -m "feat: add support for Argon2 key derivation"
   ```

### Commit Message Format

We follow conventional commits:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions or changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

### Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] No sensitive data exposed
- [ ] Platform-specific code properly isolated
- [ ] CHANGELOG.md updated

## Areas for Contribution

### High Priority

- Additional cipher implementations (AES-128, Camellia)
- Key exchange protocols (ECDH with other curves)
- Password hashing (Argon2id, scrypt)
- Windows platform optimizations
- Performance benchmarks

### psy-c Enhancements

- Additional compression algorithms
- Custom type support
- Schema validation improvements
- Code generation optimizations
- Language bindings generation

### Documentation

- Tutorial series
- Integration guides
- Performance tuning guide
- Security best practices
- API reference improvements

## Questions?

If you have questions, please:

1. Check existing issues on GitHub
2. Review the documentation
3. Open a new issue with the question label
4. Join our community discussions

## License

By contributing to Psyfer, you agree that your contributions will be licensed under the Apache License 2.0.

Thank you for contributing to Psyfer! 🔐