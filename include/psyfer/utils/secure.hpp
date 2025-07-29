#pragma once
/**
 * @file secure.hpp
 * @brief Secure utilities for cryptographic operations
 */

#include <psyfer.hpp>
#include <random>
#include <memory>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace psyfer::utils {

/**
 * @brief Secure random number generator
 * 
 * Uses platform-specific cryptographically secure random sources:
 * - /dev/urandom on Unix-like systems
 * - CryptGenRandom on Windows
 */
class secure_random {
public:
    /**
     * @brief Fill a buffer with random bytes
     * @param buffer Buffer to fill with random data
     * @return Error code on failure
     */
    [[nodiscard]] static std::error_code generate(std::span<std::byte> buffer) noexcept;
    
    /**
     * @brief Generate a random value of type T
     * @tparam T Type to generate (must be trivially copyable)
     * @return Random value or error
     */
    template<typename T>
    requires std::is_trivially_copyable_v<T>
    [[nodiscard]] static result<T> generate() noexcept {
        T value;
        auto ec = generate(std::span<std::byte>(
            reinterpret_cast<std::byte*>(&value), 
            sizeof(T)
        ));
        if (ec) {
            return std::unexpected(ec);
        }
        return value;
    }
    
    /**
     * @brief Generate a random array
     * @tparam N Size of the array
     * @return Random array or error
     */
    template<size_t N>
    [[nodiscard]] static result<std::array<std::byte, N>> generate_array() noexcept {
        std::array<std::byte, N> arr;
        auto ec = generate(arr);
        if (ec) {
            return std::unexpected(ec);
        }
        return arr;
    }
    
    /**
     * @brief Generate a cryptographic key
     * @tparam N Key size in bytes
     * @return Key array or error
     */
    template<size_t N>
    [[nodiscard]] static result<std::array<std::byte, N>> generate_key() noexcept {
        return generate_array<N>();
    }
    
    /**
     * @brief Generate a nonce/IV
     * @tparam N Nonce size in bytes
     * @return Nonce array or error
     */
    template<size_t N>
    [[nodiscard]] static result<std::array<std::byte, N>> generate_nonce() noexcept {
        return generate_array<N>();
    }

private:
    secure_random() = delete;  // Static class only
};

/**
 * @brief Secure memory allocator
 * 
 * Allocates memory that:
 * - Is locked in RAM (won't be swapped to disk)
 * - Is cleared on deallocation
 * - Has restricted access permissions where possible
 */
template<typename T>
class secure_allocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    
    secure_allocator() noexcept = default;
    
    template<typename U>
    secure_allocator(const secure_allocator<U>&) noexcept {}
    
    [[nodiscard]] T* allocate(size_type n);
    void deallocate(T* p, size_type n) noexcept;
    
    template<typename U>
    struct rebind {
        using other = secure_allocator<U>;
    };
    
    friend bool operator==(const secure_allocator&, const secure_allocator&) noexcept {
        return true;
    }
};

/**
 * @brief Secure memory buffer
 * 
 * A fixed-size buffer that:
 * - Is locked in memory (no swap)
 * - Is automatically cleared on destruction
 * - Provides protection against buffer overflows
 */
template<size_t N>
class secure_buffer {
public:
    static constexpr size_t size = N;
    
    /**
     * @brief Construct a secure buffer (zero-initialized)
     */
    secure_buffer() noexcept;
    
    /**
     * @brief Destructor (securely clears memory)
     */
    ~secure_buffer() noexcept;
    
    // Delete copy operations for safety
    secure_buffer(const secure_buffer&) = delete;
    secure_buffer& operator=(const secure_buffer&) = delete;
    
    // Allow move operations
    secure_buffer(secure_buffer&& other) noexcept;
    secure_buffer& operator=(secure_buffer&& other) noexcept;
    
    /**
     * @brief Get a span view of the buffer
     */
    [[nodiscard]] std::span<std::byte, N> span() noexcept {
        return std::span<std::byte, N>(data_, N);
    }
    
    /**
     * @brief Get a const span view of the buffer
     */
    [[nodiscard]] std::span<const std::byte, N> span() const noexcept {
        return std::span<const std::byte, N>(data_, N);
    }
    
    /**
     * @brief Get raw pointer (use with caution)
     */
    [[nodiscard]] std::byte* data() noexcept { return data_; }
    [[nodiscard]] const std::byte* data() const noexcept { return data_; }
    
    /**
     * @brief Clear the buffer (fill with zeros)
     */
    void clear() noexcept;
    
    /**
     * @brief Fill buffer from a span
     * @param source Source data (must be exactly N bytes)
     */
    void fill(std::span<const std::byte, N> source) noexcept;

private:
    alignas(16) std::byte data_[N];
    bool locked_ = false;
    
    void lock_memory() noexcept;
    void unlock_memory() noexcept;
};

/**
 * @brief Secure string type using secure allocator
 */
using secure_string = std::basic_string<char, std::char_traits<char>, 
                                        secure_allocator<char>>;

/**
 * @brief Secure vector type using secure allocator
 */
template<typename T>
using secure_vector = std::vector<T, secure_allocator<T>>;

/**
 * @brief Secure array type with automatic clearing
 */
template<typename T, size_t N>
class secure_array : public std::array<T, N> {
public:
    ~secure_array() {
        secure_clear(this->data(), N * sizeof(T));
    }
    
    // Inherit constructors
    using std::array<T, N>::array;
};

/**
 * @brief Securely clear memory
 * 
 * Uses platform-specific methods to ensure the compiler doesn't optimize
 * away the memory clearing operation.
 */
void secure_clear(void* ptr, size_t size) noexcept;

/**
 * @brief Constant-time memory comparison
 * 
 * Compares two memory regions in constant time to prevent timing attacks.
 * @return true if equal, false otherwise
 */
[[nodiscard]] bool secure_compare(
    const void* a, 
    const void* b, 
    size_t size
) noexcept;

} // namespace psyfer::utils

// Include secure key management
#include <psyfer/utils/secure_key.hpp>