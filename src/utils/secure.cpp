/**
 * @file secure.cpp
 * @brief Implementation of secure utilities
 */

#include <psyfer.hpp>
#include <fcntl.h>
#include <cstdlib>
#include <cerrno>
#include <limits>

#ifdef __APPLE__
#include <CommonCrypto/CommonRandom.h>
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#endif

namespace psyfer::utils {

// Platform-specific secure random implementation
std::error_code secure_random::generate(std::span<std::byte> buffer) noexcept {
    if (buffer.empty()) {
        return {};
    }
    
#ifdef __APPLE__
    // macOS: Use CommonCrypto
    if (CCRandomGenerateBytes(buffer.data(), buffer.size()) != kCCSuccess) {
        return make_error_code(error_code::unknown_error);
    }
    return {};
    
#elif defined(_WIN32)
    // Windows: Use CryptGenRandom
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, 
                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return make_error_code(error_code::unknown_error);
    }
    
    bool success = CryptGenRandom(hCryptProv, 
                                 static_cast<DWORD>(buffer.size()), 
                                 reinterpret_cast<BYTE*>(buffer.data()));
    
    CryptReleaseContext(hCryptProv, 0);
    
    if (!success) {
        return make_error_code(error_code::unknown_error);
    }
    return {};
    
#else
    // Unix/Linux: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return make_error_code(error_code::unknown_error);
    }
    
    size_t bytes_read = 0;
    while (bytes_read < buffer.size()) {
        ssize_t n = read(fd, 
                        buffer.data() + bytes_read, 
                        buffer.size() - bytes_read);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return make_error_code(error_code::unknown_error);
        }
        bytes_read += static_cast<size_t>(n);
    }
    
    close(fd);
    return {};
#endif
}

// Secure allocator implementation
template<typename T>
T* secure_allocator<T>::allocate(size_type n) {
    if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
        throw std::bad_alloc();
    }
    
    size_t size = n * sizeof(T);
    void* p = nullptr;
    
#ifdef _WIN32
    p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p && VirtualLock(p, size) == 0) {
        // Failed to lock, but continue anyway
    }
#else
    // Use aligned allocation for better performance
    if (posix_memalign(&p, 16, size) != 0) {
        throw std::bad_alloc();
    }
    
    // Try to lock the memory (may fail due to limits)
    mlock(p, size);
    
    // Advise kernel not to dump this memory
#ifdef MADV_DONTDUMP
    madvise(p, size, MADV_DONTDUMP);
#endif
#endif
    
    if (!p) {
        throw std::bad_alloc();
    }
    
    // Clear the allocated memory
    secure_clear(p, size);
    
    return static_cast<T*>(p);
}

template<typename T>
void secure_allocator<T>::deallocate(T* p, size_type n) noexcept {
    if (!p) return;
    
    size_t size = n * sizeof(T);
    
    // Clear memory before deallocation
    secure_clear(p, size);
    
#ifdef _WIN32
    VirtualUnlock(p, size);
    VirtualFree(p, 0, MEM_RELEASE);
#else
    munlock(p, size);
    free(p);
#endif
}

// Explicit instantiations for common types
template class secure_allocator<char>;
template class secure_allocator<std::byte>;
template class secure_allocator<uint8_t>;
template class secure_allocator<uint32_t>;
template class secure_allocator<uint64_t>;

// Secure buffer implementation
template<size_t N>
secure_buffer<N>::secure_buffer() noexcept {
    std::memset(data_, 0, N);
    lock_memory();
}

template<size_t N>
secure_buffer<N>::~secure_buffer() noexcept {
    clear();
    unlock_memory();
}

template<size_t N>
secure_buffer<N>::secure_buffer(secure_buffer&& other) noexcept {
    std::memcpy(data_, other.data_, N);
    locked_ = other.locked_;
    other.locked_ = false;
    other.clear();
}

template<size_t N>
secure_buffer<N>& secure_buffer<N>::operator=(secure_buffer&& other) noexcept {
    if (this != &other) {
        clear();
        std::memcpy(data_, other.data_, N);
        locked_ = other.locked_;
        other.locked_ = false;
        other.clear();
    }
    return *this;
}

template<size_t N>
void secure_buffer<N>::clear() noexcept {
    secure_clear(data_, N);
}

template<size_t N>
void secure_buffer<N>::fill(std::span<const std::byte, N> source) noexcept {
    std::memcpy(data_, source.data(), N);
}

template<size_t N>
void secure_buffer<N>::lock_memory() noexcept {
#ifdef _WIN32
    locked_ = VirtualLock(data_, N) != 0;
#else
    locked_ = mlock(data_, N) == 0;
#ifdef MADV_DONTDUMP
    madvise(data_, N, MADV_DONTDUMP);
#endif
#endif
}

template<size_t N>
void secure_buffer<N>::unlock_memory() noexcept {
    if (!locked_) return;
    
#ifdef _WIN32
    VirtualUnlock(data_, N);
#else
    munlock(data_, N);
#endif
    locked_ = false;
}

// Explicit instantiations for common sizes
template class secure_buffer<16>;   // 128-bit
template class secure_buffer<24>;   // 192-bit
template class secure_buffer<32>;   // 256-bit
template class secure_buffer<48>;   // 384-bit
template class secure_buffer<64>;   // 512-bit
template class secure_buffer<128>;  // 1024-bit
template class secure_buffer<256>;  // 2048-bit

// Secure memory clearing
void secure_clear(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
    
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#else
    // Use volatile to prevent optimization
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    
    // Additional barrier to prevent optimization
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

// Constant-time comparison
bool secure_compare(const void* a, const void* b, size_t size) noexcept {
    if (!a || !b) return false;
    if (size == 0) return true;
    
    const volatile unsigned char* p1 = static_cast<const volatile unsigned char*>(a);
    const volatile unsigned char* p2 = static_cast<const volatile unsigned char*>(b);
    
    volatile unsigned char result = 0;
    
    for (size_t i = 0; i < size; ++i) {
        result |= p1[i] ^ p2[i];
    }
    
    return result == 0;
}

} // namespace psyfer::utils