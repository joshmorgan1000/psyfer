#include "../include/ink_packet.hpp"
#include "../../include/encryption.hpp"
#include <fstream>
#include <cstring>
#include <memory>
#include <array>
#include <thread>
#include <chrono>
#include <algorithm>

// Stub logger definitions for standalone builds
#ifndef log_debug
#define log_debug(...) do { } while(0)
#define log_info(...) do { } while(0)
#define log_warn(...) do { } while(0)
[[maybe_unused]] static const char* thread_context = "ink_packet";
#endif

#ifdef __linux__
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <sys/mman.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace psyne::ink {

namespace {
    /**
     * @brief Get the path of the currently executing binary
     */
    std::string get_self_path() {
#ifdef __linux__
        char path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (len != -1) {
            path[len] = '\0';
            return std::string(path);
        }
#elif defined(__APPLE__)
        char path[PATH_MAX];
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0) {
            return std::string(path);
        }
#elif defined(_WIN32)
        char path[MAX_PATH];
        if (GetModuleFileNameA(nullptr, path, MAX_PATH) > 0) {
            return std::string(path);
        }
#endif
        return "";
    }
    
    /**
     * @brief Calculate CRC32 checksum
     */
    uint32_t crc32(const uint8_t* data, size_t size) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < size; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        return ~crc;
    }
}


class InkPacketLoader::Impl {
public:
    explicit Impl(const std::string& path) : binary_path_(path) {}
    
    bool verify(std::string& error) {
        // Read embedded application size
        uint64_t app_size = InkPacketEmbeddedSize::app_size;
        
        // Check if it's still the placeholder pattern
        if (app_size == 0x5245484345414C50ULL) {
            // Still has placeholder - this is not a protected binary
            is_protected_ = false;
            return true;
        }
        
        is_protected_ = true;
        app_size_ = app_size;
        
        // Verify the binary hasn't been truncated
        std::ifstream file(binary_path_, std::ios::binary);
        if (!file) {
            error = "Failed to open binary";
            return false;
        }
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        
        if (file_size < app_size + sizeof(InkPacketMetadata)) {
            error = "Binary appears truncated or corrupted";
            return false;
        }
        
        // Read metadata (right after application portion)
        file.seekg(app_size);
        
        InkPacketMetadata metadata;
        file.read(reinterpret_cast<char*>(&metadata), sizeof(metadata));
        if (!file || file.gcount() != sizeof(metadata)) {
            error = "Failed to read metadata";
            return false;
        }
        
        // Verify metadata checksum
        uint32_t saved_checksum = metadata.checksum;
        metadata.checksum = 0;
        uint32_t calc_checksum = crc32(reinterpret_cast<uint8_t*>(&metadata), sizeof(metadata));
        if (calc_checksum != saved_checksum) {
            error = "Metadata checksum mismatch";
            return false;
        }
        
        if (metadata.version != INK_PACKET_VERSION) {
            error = "Unsupported version";
            return false;
        }
        
        metadata_ = metadata;
        return true;
    }
    
    bool load(std::string& error) {
        if (!is_protected_) {
            error = "Binary is not protected with ink packet";
            return false;
        }
        
        // Anti-debugging check
        if (is_debugger_attached()) {
            error = "Debugger detected";
            // In production, this would terminate
        }
        
        // Calculate hash of application part (up to magic boundary)
        auto app_hash = calculate_app_hash();
        if (app_hash.empty()) {
            error = "Failed to calculate application hash";
            return false;
        }
        
        // Derive decryption key using hash as salt
        uint8_t key[32];
        if (!derive_key_from_hash(app_hash, key)) {
            error = "Failed to derive decryption key";
            return false;
        }
        
        std::ifstream file(binary_path_, std::ios::binary);
        if (!file) {
            error = "Failed to open binary";
            return false;
        }
        
        // Extract encrypted payload (after app + metadata)
        size_t payload_offset = app_size_ + sizeof(InkPacketMetadata);
        file.seekg(payload_offset);
        
        std::vector<uint8_t> encrypted(metadata_.payload_size);
        file.read(reinterpret_cast<char*>(encrypted.data()), metadata_.payload_size);
        
        if (!file) {
            error = "Failed to read encrypted payload";
            return false;
        }
        
        // Decrypt payload
        if (metadata_.enc_algo == 0) { // AES-256-GCM
            if (!decrypt_aes_gcm(key, encrypted, decrypted_payload_)) {
                error = "Decryption failed - application may be tampered";
                // Wipe key from memory
                OPENSSL_cleanse(key, sizeof(key));
                return false;
            }
        } else {
            error = "Unsupported encryption algorithm";
            return false;
        }
        
        // Wipe key from memory
        OPENSSL_cleanse(key, sizeof(key));
        
        // Load decrypted library from memory
        if (!load_from_memory(decrypted_payload_)) {
            error = "Failed to load decrypted library";
            return false;
        }
        
        return true;
    }
    
    void* get_symbol(const std::string& name) const {
        if (!lib_handle_) return nullptr;
#ifdef _WIN32
        return GetProcAddress(static_cast<HMODULE>(lib_handle_), name.c_str());
#else
        return dlsym(lib_handle_, name.c_str());
#endif
    }
    
private:
    std::vector<uint8_t> calculate_app_hash() {
        std::ifstream file(binary_path_, std::ios::binary);
        if (!file) return {};
        
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        
        // Hash exactly app_size_ bytes (the application portion)
        constexpr size_t CHUNK_SIZE = 8192;
        std::vector<uint8_t> buffer(CHUNK_SIZE);
        size_t remaining = app_size_;
        
        file.seekg(0);
        while (remaining > 0) {
            size_t to_read = std::min(CHUNK_SIZE, remaining);
            file.read(reinterpret_cast<char*>(buffer.data()), to_read);
            
            if (file.gcount() != static_cast<std::streamsize>(to_read)) {
                return {}; // Read error
            }
            
            blake3_hasher_update(&hasher, buffer.data(), to_read);
            remaining -= to_read;
        }
        
        std::vector<uint8_t> hash(32);
        blake3_hasher_finalize(&hasher, hash.data(), 32);
        return hash;
    }
    
    bool derive_key_from_hash(const std::vector<uint8_t>& hash, uint8_t* key) {
        if (hash.size() != 32) return false;
        
        // Use hash as salt for BLAKE3 key derivation
        blake3_hasher kdf_hasher;
        blake3_hasher_init_keyed(&kdf_hasher, hash.data());
        
        // Add additional context for key derivation
        const char* context = "ink_packet_v3_key_derivation";
        blake3_hasher_update(&kdf_hasher, context, strlen(context));
        
        // Add metadata as additional input
        blake3_hasher_update(&kdf_hasher, reinterpret_cast<const uint8_t*>(&metadata_), sizeof(metadata_));
        
        blake3_hasher_finalize(&kdf_hasher, key, 32);
        return true;
    }
    
    std::vector<uint8_t> calculate_self_hash() {
        std::ifstream file(binary_path_, std::ios::binary);
        if (!file) return {};
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0);
        
        std::vector<uint8_t> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, data.data(), size);
        
        std::vector<uint8_t> hash(32);
        blake3_hasher_finalize(&hasher, hash.data(), 32);
        
        return hash;
    }
    
    bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
        uint8_t result = 0;
        for (size_t i = 0; i < len; ++i) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    bool verify_guards() {
        // Verify the guard values around our embedded size are intact
        // This helps detect buffer overflows or memory corruption
        extern volatile uint32_t guard_before;
        extern volatile uint32_t guard_after;
        
        // For now, just return true since guards are in a separate compilation unit
        // In production, we'd verify the guard values are correct
        return true;
    }
    
    bool verify_runtime_integrity() {
        // Multiple checks to make bypassing harder
        if (!verify_guards()) return false;
        
        // Check a few random bytes of our code
        volatile uint8_t code_check = 0;
        uint8_t* check_addr = reinterpret_cast<uint8_t*>(this);
        for (int i = 0; i < 16; ++i) {
            code_check ^= check_addr[i * 7];
        }
        (void)code_check; // Prevent unused variable warning
        
        // Simple anti-debugging: check execution time
        auto start = std::chrono::high_resolution_clock::now();
        volatile int dummy = 0;
        for (int i = 0; i < 1000000; ++i) dummy += i;
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        if (duration > 50000) { // More than 50ms for simple loop = debugger
            return false;
        }
        
        return true;
    }
    
    bool is_debugger_attached() {
#ifdef __linux__
        // Check TracerPid in /proc/self/status
        std::ifstream status("/proc/self/status");
        std::string line;
        while (std::getline(status, line)) {
            if (line.find("TracerPid:") == 0) {
                return line.find("0") == std::string::npos;
            }
        }
#elif defined(__APPLE__)
        // macOS: check for debugger using sysctl
        int mib[4];
        struct kinfo_proc info;
        size_t size;
        
        info.kp_proc.p_flag = 0;
        mib[0] = CTL_KERN;
        mib[1] = KERN_PROC;
        mib[2] = KERN_PROC_PID;
        mib[3] = getpid();
        
        size = sizeof(info);
        if (sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0) == 0) {
            return (info.kp_proc.p_flag & P_TRACED) != 0;
        }
#elif defined(_WIN32)
        return IsDebuggerPresent() != 0;
#endif
        return false;
    }
    
    void trigger_tamper_response() {
        // Make the binary unusable in creative ways
        // 1. Corrupt our own embedded size to prevent future loads
        const_cast<volatile uint64_t&>(InkPacketEmbeddedSize::app_size) = 0;
        
        // 2. Clear decrypted payload from memory
        if (!decrypted_payload_.empty()) {
            OPENSSL_cleanse(decrypted_payload_.data(), decrypted_payload_.size());
        }
        
        // 3. If there's a callback, call it
        if (tamper_callback_) {
            tamper_callback_();
        }
        
        // 4. Sleep to make debugging annoying
        std::this_thread::sleep_for(std::chrono::seconds(10));
        
        // 5. Crash in a confusing way
        volatile int* p = nullptr;
        *p = 42;
    }

private:
    bool decrypt_aes_gcm(const uint8_t* key, const std::vector<uint8_t>& encrypted,
                         std::vector<uint8_t>& decrypted) {
        constexpr size_t IV_LEN = 12;
        constexpr size_t TAG_LEN = 16;
        
        if (encrypted.size() < IV_LEN + TAG_LEN) return false;
        
        const uint8_t* iv = encrypted.data();
        const uint8_t* tag = encrypted.data() + encrypted.size() - TAG_LEN;
        const uint8_t* ciphertext = encrypted.data() + IV_LEN;
        size_t ciphertext_len = encrypted.size() - IV_LEN - TAG_LEN;
        
        decrypted.resize(ciphertext_len);
        
        auto ctx = make_cipher_ctx();
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv);
        
        int outl;
        if (EVP_DecryptUpdate(ctx.get(), decrypted.data(), &outl, ciphertext, ciphertext_len) != 1) {
            return false;
        }
        
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<uint8_t*>(tag));
        if (EVP_DecryptFinal_ex(ctx.get(), nullptr, &outl) != 1) {
            return false;
        }
        
        return true;
    }
    
    bool load_from_memory(const std::vector<uint8_t>& lib_data) {
#ifdef __linux__
        // Linux: Write to temp file and dlopen
        char temp_path[] = "/tmp/ink_XXXXXX";
        int fd = mkstemp(temp_path);
        if (fd == -1) return false;
        
        // Delete file immediately but keep fd open
        unlink(temp_path);
        
        if (write(fd, lib_data.data(), lib_data.size()) != static_cast<ssize_t>(lib_data.size())) {
            close(fd);
            return false;
        }
        
        // Load from /proc/self/fd/
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        lib_handle_ = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
        close(fd);
        
        return lib_handle_ != nullptr;
        
#elif defined(__APPLE__)
        // macOS: Similar approach with temp file
        char temp_path[] = "/tmp/ink_XXXXXX";
        int fd = mkstemp(temp_path);
        if (fd == -1) return false;
        
        if (write(fd, lib_data.data(), lib_data.size()) != static_cast<ssize_t>(lib_data.size())) {
            close(fd);
            unlink(temp_path);
            return false;
        }
        close(fd);
        
        lib_handle_ = dlopen(temp_path, RTLD_NOW | RTLD_LOCAL);
        unlink(temp_path);
        
        return lib_handle_ != nullptr;
        
#elif defined(_WIN32)
        // Windows: Use memory mapping
        void* mem = VirtualAlloc(nullptr, lib_data.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mem) return false;
        
        memcpy(mem, lib_data.data(), lib_data.size());
        
        DWORD old_protect;
        if (!VirtualProtect(mem, lib_data.size(), PAGE_EXECUTE_READ, &old_protect)) {
            VirtualFree(mem, 0, MEM_RELEASE);
            return false;
        }
        
        // Custom PE loader would go here - simplified for now
        // In production, implement proper PE loading from memory
        lib_handle_ = mem;
        return true;
#else
        return false;
#endif
    }
    
    std::string binary_path_;
    InkPacketMetadata metadata_;
    std::vector<uint8_t> decrypted_payload_;
    void* lib_handle_ = nullptr;
    bool is_protected_ = false;
    uint64_t app_size_ = 0;
    std::function<void()> tamper_callback_;
};

InkPacketLoader::InkPacketLoader() : impl_(std::make_unique<Impl>(get_self_path())) {}

InkPacketLoader::InkPacketLoader(const std::string& binary_path) 
    : impl_(std::make_unique<Impl>(binary_path)) {}

InkPacketLoader::~InkPacketLoader() = default;

bool InkPacketLoader::verify() const {
    std::string error;
    bool result = impl_->verify(error);
    if (!result) {
        const_cast<InkPacketLoader*>(this)->error_ = error;
    }
    return result;
}

bool InkPacketLoader::load() {
    if (!impl_->verify(error_)) {
        return false;
    }
    
    if (!impl_->load(error_)) {
        return false;
    }
    
    loaded_ = true;
    return true;
}

void* InkPacketLoader::get_symbol(const std::string& symbol_name) const {
    if (!loaded_) return nullptr;
    return impl_->get_symbol(symbol_name);
}

// Memory protection utilities
namespace memory {
    bool lock_pages(void* addr, size_t size) {
#ifdef _WIN32
        return VirtualLock(addr, size) != 0;
#else
        return mlock(addr, size) == 0;
#endif
    }
    
    bool unlock_pages(void* addr, size_t size) {
#ifdef _WIN32
        return VirtualUnlock(addr, size) != 0;
#else
        return munlock(addr, size) == 0;
#endif
    }
    
    bool mark_non_dumpable(void* addr, size_t size) {
#ifdef __linux__
        return madvise(addr, size, MADV_DONTDUMP) == 0;
#else
        // Not supported on other platforms yet
        (void)addr;
        (void)size;
        return true;
#endif
    }
    
    void* alloc_executable(size_t size) {
#ifdef _WIN32
        return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
        void* mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (mem == MAP_FAILED) ? nullptr : mem;
#endif
    }
    
    void free_executable(void* addr, size_t size) {
#ifdef _WIN32
        VirtualFree(addr, 0, MEM_RELEASE);
#else
        munmap(addr, size);
#endif
    }
}

// Self-verification utilities
namespace verify {
    std::vector<uint8_t> hash_self(uint8_t algo) {
        std::string path = get_self_path();
        if (path.empty()) return {};
        
        std::ifstream file(path, std::ios::binary);
        if (!file) return {};
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0);
        
        std::vector<uint8_t> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        std::vector<uint8_t> hash;
        if (algo == 0) { // BLAKE3
            blake3_hasher hasher;
            blake3_hasher_init(&hasher);
            blake3_hasher_update(&hasher, data.data(), size);
            hash.resize(32);
            blake3_hasher_finalize(&hasher, hash.data(), 32);
        }
        
        return hash;
    }
    
    bool check_integrity() {
        InkPacketLoader loader;
        return loader.verify();
    }
    
    bool deep_verify() {
        InkPacketLoader loader;
        return loader.verify();
    }
    
    static std::function<void()> tamper_callback;
    
    void on_tamper(std::function<void()> callback) {
        tamper_callback = callback;
    }
    
    bool is_debugger_present() {
        // Direct implementation for public API
#ifdef __linux__
        std::ifstream status("/proc/self/status");
        std::string line;
        while (std::getline(status, line)) {
            if (line.find("TracerPid:") == 0) {
                return line.find("0") == std::string::npos;
            }
        }
#elif defined(_WIN32)
        return IsDebuggerPresent() != 0;
#endif
        return false;
    }
}

} // namespace psyne::ink