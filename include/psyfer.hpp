#ifndef PSYFER_MAIN_HPP
#define PSYFER_MAIN_HPP

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>
#include <memory>
#include <expected>
#include <system_error>
#include <thread>
#include <atomic>
#include <sstream>
#include <iostream>
#include <format>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <chrono>
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
#include <goldenhash.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
namespace psyfer {
constexpr uint32_t VERSION_MAJOR = 1;
constexpr uint32_t VERSION_MINOR = 0;
constexpr uint32_t VERSION_PATCH = 0;

// Error codes for psyfer operations
enum class error_code {
    success = 0,
    invalid_buffer_size,
    buffer_too_small,
    decompression_failed,
    encryption_failed,
    decryption_failed,
    invalid_key_size,
    invalid_parameter,
    invalid_nonce_size,
    invalid_tag_size,
    hash_mismatch,
    compression_failed,
    memory_allocation_failed,
    not_implemented,
    crypto_error,
    unknown_error,
    invalid_argument,
    authentication_failed
};
inline static std::string message(int ev) {
    switch (static_cast<error_code>(ev)) {
        case error_code::success:
            return "Success";
        case error_code::invalid_argument:
            return "Invalid argument";
        case error_code::invalid_key_size:
            return "Invalid key size";
        case error_code::invalid_nonce_size:
            return "Invalid nonce size";
        case error_code::invalid_tag_size:
            return "Invalid tag size";
        case error_code::invalid_buffer_size:
            return "Invalid buffer size";
        case error_code::encryption_failed:
            return "Encryption failed";
        case error_code::decryption_failed:
            return "Decryption failed";
        case error_code::authentication_failed:
            return "Authentication failed";
        case error_code::compression_failed:
            return "Compression failed";
        case error_code::decompression_failed:
            return "Decompression failed";
        case error_code::hash_mismatch:
            return "Hash mismatch";
        case error_code::memory_allocation_failed:
            return "Memory allocation failed";
        case error_code::not_implemented:
            return "Not implemented";
        case error_code::crypto_error:
            return "Cryptographic operation failed";
        case error_code::buffer_too_small:
            return "Buffer too small";
        case error_code::unknown_error:
            return "Unknown error";
        default:
            return "Unknown error code";
    }
}
inline std::error_code make_error_code(error_code e) noexcept {
    return std::error_code(static_cast<int>(e), std::generic_category());
}
// Result type alias
template<typename T>
using result = std::expected<T, std::error_code>;

}
template<typename T>
concept HasEncryptedSize = requires(const T& t) {
    { t.encrypted_size() } -> std::convertible_to<size_t>;
};
template<typename T>
concept HasDecrypt = requires(std::span<const std::byte> src, T* target, std::span<const std::byte> key) {
    { T::decrypt(src, target, key) } -> std::convertible_to<size_t>;
};
template<typename T>
concept Streamable=requires(std::ostream &os,T const &t){{os<<t}->std::convertible_to<std::ostream &>;};
template<typename T> concept HasToJson=requires(T t){{t.toJson()}->std::convertible_to<std::string>;};
template<typename T> concept HasToString=requires(T t){{t.toString()}->std::convertible_to<std::string>;};
template<typename T> concept EssentiallyStreamable=Streamable<T>||HasToJson<T>||HasToString<T>;
struct ProgressBar { std::string id; std::string thread_name; std::string header; std::string start_time_str;
float progress; int width; unsigned long start_line; uint64_t start_time; };
enum class LogLevel { TRACE = 0, DEBUG = 1, INFO = 2, WARN = 3, ERROR = 4 };
struct GlobalContext { std::atomic<uint64_t> stdout_current_line{0};
static thread_local std::string thread_context; std::atomic<uint64_t> next_ticket{0};
std::atomic<uint64_t> currently_serving{0}; std::atomic<uint64_t> threadCounter{0};
std::atomic<bool> stopFlag{false}; std::atomic<bool> standalone{true};
std::mutex progress_mutex; std::atomic<bool> banner_animation_done{true};
std::shared_ptr<std::thread> crypto_hash_init_ptr; size_t num_cpu_cores = std::thread::hardware_concurrency();
static constexpr uint8_t initialObfuscation[4] = {0x13, 0x6E, 0x68, 0x70}; LogLevel global_log_level = LogLevel::TRACE;
std::unordered_map<std::string, ProgressBar> progress_bars; std::atomic<bool> banner_shown{false}; };
GlobalContext &getGlobalContext(); extern thread_local std::string &thread_context;
std::string get_thread_context();
std::function<void(float)> log_progress(const std::string &header, const std::string &thread_name = "");
template <typename T> requires Streamable<T> inline static void
concat_multi_parameter_inputs(std::stringstream &currentstream, T first) {
if constexpr (Streamable<T>) currentstream << first; else if constexpr (HasToJson<T>)
currentstream << first.toJson().dump(); else if constexpr (HasToString<T>) currentstream << first.toString(); }
template <typename T, typename... Args> requires Streamable<T>
static void concat_multi_parameter_inputs(std::stringstream &currentstream, T first, Args... args) {
if constexpr (Streamable<T>) currentstream << first; else if constexpr (HasToJson<T>)
currentstream << first.toJson().dump(); else if constexpr (HasToString<T>) currentstream << first.toString();
if constexpr (sizeof...(args) > 0) concat_multi_parameter_inputs(currentstream, args...); }
void set_internal_log_level(LogLevel level); void log_message(LogLevel level, const std::string& message);
template <typename... Args> static void log_message(LogLevel level, const std::string& format_str, Args&&... args) {
std::string formatted = std::vformat(format_str, std::make_format_args(args...));
log_message(level, formatted); } template <typename... Args>
static void log_message(LogLevel level, const char* format_str, Args&&... args) {
std::string formatted = std::vformat(format_str, std::make_format_args(args...));
log_message(level, formatted); } template <typename T, typename... Args>
requires EssentiallyStreamable<T> && (!std::is_same_v<std::decay_t<T>, const char*>) && (!std::is_same_v<std::decay_t<T>, std::string>)
static void log_message(LogLevel level, T first, Args... args) { if (getGlobalContext().global_log_level > level) return;
std::stringstream msg_stream; concat_multi_parameter_inputs(msg_stream, first, args...);
log_message(level, msg_stream.str()); } void log_info(const std::string& message);
template <typename... Args> static void log_info(const std::string& format_str, Args&&... args) {
log_message(LogLevel::INFO, format_str, std::forward<Args>(args)...); }
template <typename... Args> static void log_info(const char* format_str, Args&&... args) {
    log_message(LogLevel::INFO, format_str, std::forward<Args>(args)...); }
template <typename T, typename... Args>
    requires EssentiallyStreamable<T> && (!std::is_same_v<std::decay_t<T>, const char*>) && (!std::is_same_v<std::decay_t<T>, std::string>)
static void log_info(T first, Args... args) {
    log_message(LogLevel::INFO, first, args...); }
void log_error(const std::string& message);
template <typename... Args>
static void log_error(const std::string& format_str, Args&&... args) {
    log_message(LogLevel::ERROR, format_str, std::forward<Args>(args)...); }
template <typename... Args>
static void log_error(const char* format_str, Args&&... args) {
    log_message(LogLevel::ERROR, format_str, std::forward<Args>(args)...); }
template <typename T, typename... Args>
    requires EssentiallyStreamable<T> && (!std::is_same_v<std::decay_t<T>, const char*>) && (!std::is_same_v<std::decay_t<T>, std::string>)
static void log_error(T first, Args... args) {
    log_message(LogLevel::ERROR, first, args...); }
void log_warn(const std::string& message);
template <typename... Args>
static void log_warn(const std::string& format_str, Args&&... args) {
    log_message(LogLevel::WARN, format_str, std::forward<Args>(args)...); }
template <typename... Args>
static void log_warn(const char* format_str, Args&&... args) {
    log_message(LogLevel::WARN, format_str, std::forward<Args>(args)...); }
template <typename T, typename... Args>
    requires EssentiallyStreamable<T> && (!std::is_same_v<std::decay_t<T>, const char*>) && (!std::is_same_v<std::decay_t<T>, std::string>)
static void log_warn(T first, Args... args) {
    log_message(LogLevel::WARN, first, args...); }
void log_debug(const std::string& message);
template <typename... Args>
static void log_debug(const std::string& format_str, Args&&... args) {
    log_message(LogLevel::DEBUG, format_str, std::forward<Args>(args)...); }
template <typename... Args>
static void log_debug(const char* format_str, Args&&... args) {
    log_message(LogLevel::DEBUG, format_str, std::forward<Args>(args)...); }
template <typename T, typename... Args>
    requires EssentiallyStreamable<T> && (!std::is_same_v<std::decay_t<T>, const char*>) && (!std::is_same_v<std::decay_t<T>, std::string>)
static void log_debug(T first, Args... args) {
    log_message(LogLevel::DEBUG, first, args...); }
void log_trace(const std::string& message);
template <typename... Args>
static void log_trace(const std::string& format_str, Args&&... args) {
    log_message(LogLevel::TRACE, format_str, std::forward<Args>(args)...); }
template <typename... Args>
static void log_trace(const char* format_str, Args&&... args) {
    log_message(LogLevel::TRACE, format_str, std::forward<Args>(args)...); }
template <typename T, typename... Args>
    requires EssentiallyStreamable<T> && (!std::is_same_v<std::decay_t<T>, const char*>) && (!std::is_same_v<std::decay_t<T>, std::string>)
static void log_trace(T first, Args... args) {
    log_message(LogLevel::TRACE, first, args...); }
class StreamLogger { private: LogLevel level_; std::stringstream stream_;
public: explicit StreamLogger(LogLevel level) : level_(level) {}
    template<typename T> StreamLogger& operator<<(T&& value) {
        stream_ << std::forward<T>(value); return *this; }
    ~StreamLogger() { log_message(level_, stream_.str()); }
    StreamLogger(const StreamLogger&) = delete;
    StreamLogger& operator=(const StreamLogger&) = delete;
    StreamLogger(StreamLogger&&) = default;
    StreamLogger& operator=(StreamLogger&&) = default; };
inline StreamLogger log_info() { return StreamLogger(LogLevel::INFO); }
inline StreamLogger log_warn() { return StreamLogger(LogLevel::WARN); }
inline StreamLogger log_error() { return StreamLogger(LogLevel::ERROR); }
inline StreamLogger log_debug() { return StreamLogger(LogLevel::DEBUG); }
inline StreamLogger log_trace() { return StreamLogger(LogLevel::TRACE); }
inline std::string to_binary(uint8_t* data, size_t size) {
std::stringstream ss; for (size_t i = 0; i < size; ++i) {
ss << std::bitset<8>(data[i]); } return ss.str(); }
template<typename T> class tracked_range { struct iterator {
T current_; T end_; T step_; std::function<void(float)>* progress_fn_;
T total_iterations_; T current_iteration_; iterator(T current, T end, T step, std::function<void(float)>* fn, T total)
        : current_(current), end_(end), step_(step), progress_fn_(fn), 
total_iterations_(total), current_iteration_(0) {} T operator*() const { return current_; }
iterator& operator++() { current_ += step_; current_iteration_++; if (progress_fn_ && *progress_fn_) {
float progress = static_cast<float>(current_iteration_) / static_cast<float>(total_iterations_);
(*progress_fn_)(progress); } return *this; }
bool operator!=(const iterator& other) const { return (step_ > 0) ? (current_ < other.end_) : (current_ > other.end_); } };
T start_; T end_; T step_; std::string header_; std::function<void(float)> progress_fn_; T total_iterations_;
public: tracked_range(T start, T end, const std::string& header, T step = 1)
    : start_(start), end_(end), step_(step), header_(header) {
    if (step_ == 0) { log_error("tracked_range: step cannot be zero!");
        step_ = 1; } total_iterations_ = (end_ - start_) / step_;
    if ((end_ - start_) % step_ != 0) { total_iterations_++; }
    progress_fn_ = log_progress(header_); progress_fn_(0.0f); }
~tracked_range() { if (progress_fn_) progress_fn_(1.0f); }
    iterator begin() { return iterator(start_, end_, step_, &progress_fn_, total_iterations_); }
    iterator end() { return iterator(end_, end_, step_, nullptr, total_iterations_); } };
template<typename T> tracked_range<T> track_range(T start, T end, const std::string& header, T step = 1) {
    return tracked_range<T>(start, end, header, step); }
template<typename T> tracked_range<T> track_range(T count, const std::string& header) {
    return tracked_range<T>(0, count, header, 1); }
template<typename Container> class tracked_container { struct iterator {
typename Container::const_iterator current_; typename Container::const_iterator end_;
std::function<void(float)>* progress_fn_; size_t total_size_; size_t current_index_;
iterator(typename Container::const_iterator current, typename Container::const_iterator end,
std::function<void(float)>* fn, size_t total) : current_(current), end_(end), progress_fn_(fn), 
total_size_(total), current_index_(0) {} auto operator*() const { return *current_; }
iterator& operator++() { ++current_; ++current_index_; if (progress_fn_ && *progress_fn_ && total_size_ > 0) {
float progress = static_cast<float>(current_index_) / static_cast<float>(total_size_);
(*progress_fn_)(progress); } return *this; } bool operator!=(const iterator& other) const {
return current_ != other.end_; } }; const Container& container_; std::string header_;
std::function<void(float)> progress_fn_; public:
tracked_container(const Container& c, const std::string& header)
: container_(c), header_(header) { progress_fn_ = log_progress(header_);
progress_fn_(0.0f); } ~tracked_container() { if (progress_fn_) { progress_fn_(1.0f); } }
iterator begin() { return iterator(container_.begin(), container_.end(), &progress_fn_, container_.size()); }
iterator end() { return iterator(container_.end(), container_.end(), nullptr, container_.size()); } };
template<typename Container> tracked_container<Container>
track_container(const Container& c, const std::string& header) {
return tracked_container<Container>(c, header); } inline void stdout_lock()
{ uint64_t ticket = getGlobalContext().next_ticket.fetch_add(1);
uint64_t current = getGlobalContext().currently_serving.load();
while (current != ticket) { getGlobalContext().currently_serving.wait(current);
current = getGlobalContext().currently_serving.load(); } }
inline void stdout_unlock() { getGlobalContext().currently_serving.fetch_add(1);
getGlobalContext().currently_serving.notify_all(); }
namespace psyfer {
using namespace goldenhash;
class SecureKey {
private:
    uint8_t* private_key = nullptr;
    uint8_t* public_key = nullptr;
    size_t key_size_;
    void secure_alloc() {
        private_key = (uint8_t*)OPENSSL_secure_malloc(key_size_);
        if (!private_key) {
            throw std::runtime_error("Failed to allocate secure memory for private key");
        }
        std::memset(private_key, 0, key_size_); // Initialize to zero
        public_key = (uint8_t*)OPENSSL_secure_malloc(key_size_);
        if (!public_key) {
            OPENSSL_secure_free(private_key);
            throw std::runtime_error("Failed to allocate secure memory for public key");
        }
    }
    void secure_free() {
        if (private_key) {
            OPENSSL_cleanse(private_key, key_size_);
            OPENSSL_secure_free(private_key);
            private_key = nullptr;
        }
        if (public_key) {
            OPENSSL_cleanse(public_key, key_size_);
            OPENSSL_secure_free(public_key);
            public_key = nullptr;
        }
    }
public:
    enum class KeyType {
        AES_128,
        AES_256,
        ChaCha20,
        Poly1305,
        HMAC_SHA256,
        HMAC_SHA512,
        X25519,
        ED25519
    };
    SecureKey() = default;
    SecureKey(size_t key_size) : private_key(nullptr), key_size_(key_size) {
        secure_alloc();
        // Use openSSL to generate a secure random key
        if (RAND_bytes(private_key, key_size_) != 1) {
            secure_free();
            throw std::runtime_error("Failed to generate secure random key");
        }
    }
    SecureKey(KeyType type, bool generate = true) 
        : key_size_(type == KeyType::AES_128 ? 16 : (type == KeyType::AES_256 ? 32 : 64)) {
        if (generate) {
            secure_alloc();
            if (RAND_bytes(private_key, key_size_) != 1) {
                secure_free();
                throw std::runtime_error("Failed to generate secure random key");
            }
        } else {
            private_key = nullptr; // No allocation
        }
    }
    SecureKey(std::span<const uint8_t> private_key_, std::span<const uint8_t> public_key) {
        if (private_key_.size() != key_size_ || public_key.size() != key_size_) {
            throw std::invalid_argument("Key sizes do not match");
        }
        secure_alloc();
        std::memcpy(this->private_key, private_key_.data(), key_size_);
        std::memcpy(this->public_key, public_key.data(), key_size_);
    }
    ~SecureKey() {
        secure_free();
    }
    SecureKey(const SecureKey&) = delete; // Disable copy constructor
    SecureKey& operator=(const SecureKey&) = delete; // Disable copy assignment
    SecureKey(SecureKey&& other) noexcept : private_key(other.private_key), key_size_(other.key_size_) {
        other.private_key = nullptr; // Transfer ownership
    }
    SecureKey& operator=(SecureKey&& other) noexcept {
        if (this != &other) {
            secure_free(); // Clean up current key
            key_size_ = other.key_size_;
            private_key = other.private_key;
            other.private_key = nullptr; // Transfer ownership
        }
        return *this;
    }
    [[nodiscard]] std::span<const uint8_t> get_key() const noexcept {
        return std::span<const uint8_t>(private_key, key_size_);
    }
    [[nodiscard]] size_t size() const noexcept {
        return key_size_;
    }
    void clear() noexcept {
        if (private_key) {
            OPENSSL_cleanse(private_key, key_size_);
            std::memset(private_key, 0, key_size_); // Clear sensitive data
        }
    }
    [[nodiscard]] bool is_empty() const noexcept {
        if (!private_key) return true;
        return false;
    }
    [[nodiscard]] bool operator==(const SecureKey& other) const noexcept {
        if (key_size_ != other.key_size_) return false;
        return std::equal(private_key, private_key + key_size_, other.private_key);
    }
    [[nodiscard]] std::string to_hex() const {
        std::string hex_str;
        hex_str.reserve(key_size_ * 2);
        for (size_t i = 0; i < key_size_; ++i) {
            hex_str += "0123456789abcdef"[private_key[i] >> 4];
            hex_str += "0123456789abcdef"[private_key[i] & 0x0F];
        }
        return hex_str;
    }
    [[nodiscard]] static SecureKey from_hex(const std::string& hex_str) {
        if (hex_str.size() % 2 != 0) {
            throw std::invalid_argument("Hex string must have an even length");
        }
        size_t key_size = hex_str.size() / 2;
        SecureKey key(key_size);

        for (size_t i = 0; i < key_size; ++i) {
            char byte_str[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
            unsigned long byte_value = strtoul(byte_str, nullptr, 16);
            if (byte_value > 255) {
                throw std::invalid_argument("Invalid hex string");
            }
            key.private_key[i] = static_cast<uint8_t>(byte_value);
        }
        return key;
    }
    [[nodiscard]] static SecureKey generate(size_t key_size) {
        SecureKey key(key_size);
        if (RAND_bytes(key.private_key, key_size) != 1) {
            throw std::runtime_error("Failed to generate secure random key");
        }
        return key;
    }
    [[nodiscard]] static SecureKey from_password(
        const std::string& password,
        const std::span<const uint8_t> salt,
        uint32_t iterations = 100000
    ) {
        if (salt.size() < 8) {
            throw std::invalid_argument("Salt must be at least 8 bytes");
        }
        SecureKey key(32); // 32 bytes for SHA-256
        if (PKCS5_PBKDF2_HMAC(
            password.c_str(), password.size(),
            salt.data(), salt.size(),
            iterations, EVP_sha256(),
            key.size(), key.private_key
        ) != 1) {
            throw std::runtime_error("Failed to derive key from password");
        }
        return key;
    }
    [[nodiscard]] static SecureKey from_protected(
        const std::span<const uint8_t> encrypted_data,
        const std::span<const uint8_t, 32> protection_key
    ) {
        if (encrypted_data.size() < 32) {
            throw std::invalid_argument("Encrypted data must be at least 32 bytes");
        }
        SecureKey key(32);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        if (EVP_DecryptInit_ex(
            ctx, EVP_aes_256_gcm(), nullptr,
            protection_key.data(), nullptr
        ) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }
        int outlen;
        if (EVP_DecryptUpdate(
            ctx, key.private_key, &outlen,
            encrypted_data.data(), static_cast<int>(encrypted_data.size())
        ) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed");
        }
        if (EVP_DecryptFinal_ex(ctx, key.private_key + outlen, &outlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption finalization failed");
        }
        EVP_CIPHER_CTX_free(ctx);
        return key;
    }
    uint8_t* get_private_key() const noexcept {
        return private_key;
    }
    uint8_t* get_public_key() const noexcept {
        return public_key;
    }
};

class Encryptor {
private:
    std::unique_ptr<SecureKey> key_;
    std::unique_ptr<SecureKey> sign_keypair;
    std::unique_ptr<SecureKey> enc_keypair;
    std::unique_ptr<SecureKey> public_key_;
public:
    Encryptor(bool generate_key = true) {
        if (generate_key) {
            key_ = std::make_unique<SecureKey>(SecureKey::generate(32)); // 32 bytes for AES-256
        } else {
            key_ = std::make_unique<SecureKey>(SecureKey::KeyType::AES_256, false);
        }
    }
    Encryptor(const SecureKey& key) = delete; // Cannot copy SecureKey
    Encryptor(SecureKey&& key) 
        : key_(std::make_unique<SecureKey>(std::move(key))) {}
    Encryptor(const Encryptor&) = delete; // Disable copy constructor
    Encryptor& operator=(const Encryptor&) = delete; // Disable copy assignment
    Encryptor(Encryptor&& other) noexcept 
        : key_(std::move(other.key_)), public_key_(std::move(other.public_key_)) {
        other.key_ = nullptr; // Transfer ownership
    }
    Encryptor& operator=(Encryptor&& other) noexcept {
        if (this != &other) {
            key_ = std::move(other.key_);
            public_key_ = std::move(other.public_key_);
            other.key_ = nullptr; // Transfer ownership
        }
        return *this;
    }
    void import_key(const std::string& key_pair, bool is_private_key) {
        if (is_private_key) {
            if (key_pair.length() != 64) throw std::invalid_argument("Key size must be 64 std::string");
            std::vector<uint8_t> sign_key(32);
            std::vector<uint8_t> enc_key(32);
            std::memcpy(sign_key.data(), key_pair.data(), 32);
            std::memcpy(enc_key.data(), key_pair.data() + 32, 32);
            std::vector<uint8_t> sign_pubkey(32);
            std::vector<uint8_t> enc_pubkey(32);
            EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key.data(), sign_key.size());
            if (!pkey) throw std::runtime_error("Failed to create private key");
            size_t pubkey_len = 32;
            if (EVP_PKEY_get_raw_public_key(pkey, sign_pubkey.data(), &pubkey_len) != 1) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to get public key");
            }
            EVP_PKEY_free(pkey);
            sign_keypair = std::make_unique<SecureKey>(std::span<const uint8_t>(sign_pubkey.data(), sign_pubkey.size()), std::span<const uint8_t>(sign_key.data(), sign_key.size()));
            EVP_PKEY* pkey2 = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, enc_key.data(), enc_key.size());
            if (!pkey2) throw std::runtime_error("Failed to create private key");
            size_t pubkey_len2 = 32;
            if (EVP_PKEY_get_raw_public_key(pkey2, enc_pubkey.data(), &pubkey_len2) != 1) {
                EVP_PKEY_free(pkey2);
                throw std::runtime_error("Failed to get public key");
            }
            EVP_PKEY_free(pkey2);
            enc_keypair = std::make_unique<SecureKey>(std::span<const uint8_t>(enc_pubkey.data(), enc_pubkey.size()), std::span<const uint8_t>(enc_key.data(), enc_key.size()));
        } else {
            if (key_pair.length() != 64) throw std::invalid_argument("Key size must be 64 std::string");
            std::vector<uint8_t> sign_key(32);
            std::vector<uint8_t> enc_key(32);
            std::memcpy(sign_key.data(), key_pair.data(), 32);
            std::memcpy(enc_key.data(), key_pair.data() + 32, 32);
            // These are just public keys, no need to derive private keys
            sign_keypair = std::make_unique<SecureKey>(std::span<const uint8_t>(sign_key.data(), sign_key.size()), std::span<const uint8_t>(sign_key.data(), sign_key.size()));
            enc_keypair = std::make_unique<SecureKey>(std::span<const uint8_t>(enc_key.data(), enc_key.size()), std::span<const uint8_t>(enc_key.data(), enc_key.size()));
        }
    }
    [[nodiscard]] const SecureKey& get_key() const noexcept {
        return *key_;
    }
    [[nodiscard]] const SecureKey& get_public_key() const noexcept {
        return *public_key_;
    }
    [[nodiscard]] const SecureKey& get_sign_keypair() const noexcept {
        return *sign_keypair;
    }
    [[nodiscard]] const SecureKey& get_enc_keypair() const noexcept {
        return *enc_keypair;
    }
    void encrypt(
        std::span<const uint8_t> plaintext,
        std::span<uint8_t> ciphertext
    ) const {
        if (ciphertext.size() < plaintext.size() + 16 + 12) { // 16 for tag, 12 for IV
            throw std::runtime_error("Ciphertext buffer too small");
        }
        
        // Generate random IV (12 bytes for GCM)
        uint8_t iv[12];
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            throw std::runtime_error("Failed to generate IV");
        }
        
        // Copy IV to beginning of ciphertext
        std::memcpy(ciphertext.data(), iv, sizeof(iv));
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set IV length");
        }
        
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_->get_key().data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set key and IV");
        }
        
        int outlen;
        if (EVP_EncryptUpdate(ctx, ciphertext.data() + 12, &outlen, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed");
        }
        
        int tmplen;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + 12 + outlen, &tmplen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption finalization failed");
        }
        outlen += tmplen;
        
        // Get and append tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + 12 + outlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to get GCM tag");
        }
        
        EVP_CIPHER_CTX_free(ctx);
    }
    void decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<uint8_t> plaintext
    ) const {
        if (ciphertext.size() < 16 + 12) { // 16 for tag, 12 for IV
            throw std::runtime_error("Ciphertext buffer too small");
        }
        if (plaintext.size() < ciphertext.size() - 16 - 12) {
            throw std::runtime_error("Plaintext buffer too small");
        }
        
        // Extract IV from beginning of ciphertext
        uint8_t iv[12];
        std::memcpy(iv, ciphertext.data(), sizeof(iv));
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set IV length");
        }
        
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_->get_key().data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set key and IV");
        }
        
        // Ciphertext starts after IV, tag is at the end
        int ciphertext_len = static_cast<int>(ciphertext.size() - 12 - 16);
        
        int outlen;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data() + 12, ciphertext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed");
        }
        
        // Set tag before finalizing
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(ciphertext.data() + ciphertext.size() - 16)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set GCM tag");
        }
        
        int tmplen;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &tmplen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption finalization failed - authentication failed");
        }
        outlen += tmplen;
        
        EVP_CIPHER_CTX_free(ctx);
    }
    std::span<const uint8_t> sign(
        std::span<const uint8_t> data
    ) const {
        if (!sign_keypair) {
            throw std::runtime_error("Signing keypair not initialized");
        }
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                       sign_keypair->get_private_key(), 32);
        if (!pkey) {
            throw std::runtime_error("Failed to create private key");
        }
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create signing context");
        }
        if (EVP_PKEY_sign_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize signing");
        }
        size_t siglen;
        if (EVP_PKEY_sign(ctx, nullptr, &siglen, data.data(), data.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to determine signature length");
        }
        std::vector<uint8_t> signature(siglen);
        if (EVP_PKEY_sign(ctx, signature.data(), &siglen, data.data(), data.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Signing failed");
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return std::span<const uint8_t>(signature.data(), siglen);
    }
    bool verify(
        std::span<const uint8_t> data,
        std::span<const uint8_t> signature
    ) const {       
        if (!sign_keypair) {
            throw std::runtime_error("Signing keypair not initialized");
        }
        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, 
                                                      sign_keypair->get_public_key(), 32);
        if (!pkey) {
            throw std::runtime_error("Failed to create public key");
        }
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create verification context");
        }
        if (EVP_PKEY_verify_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize verification");
        }
        int result = EVP_PKEY_verify(ctx, signature.data(), signature.size(), data.data(), data.size());
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        if (result <= 0) {
            if (result < 0) {
                throw std::runtime_error("Verification failed");
            }
            return false; // Signature does not match
        }
        return true; // Signature matches
    }
    std::vector<uint8_t> sha256(
        std::span<const uint8_t> data
    ) const {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        if (SHA256(data.data(), data.size(), hash.data()) == nullptr) {
            throw std::runtime_error("SHA-256 hashing failed");
        }
        return hash;
    }
    std::vector<uint8_t> sha512(
        std::span<const uint8_t> data
    ) const {
        std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);
        if (SHA512(data.data(), data.size(), hash.data()) == nullptr) {
            throw std::runtime_error("SHA-512 hashing failed");
        }
        return hash;
    }
    std::vector<uint8_t> hmac_sha256(
        std::span<const uint8_t> data
    ) const {
        if (!key_) {
            throw std::runtime_error("HMAC key not initialized");
        }
        std::vector<uint8_t> hmac(SHA256_DIGEST_LENGTH);
        unsigned int hmac_len;
        if (HMAC(EVP_sha256(), key_->get_key().data(), key_->size(),
                 data.data(), data.size(), hmac.data(), &hmac_len) == nullptr) {
            throw std::runtime_error("HMAC-SHA256 failed");
        }
        hmac.resize(hmac_len);
        return hmac;
    }
    std::vector<uint8_t> hmac_sha512(
        std::span<const uint8_t> data
    ) const {
        if (!key_) {
            throw std::runtime_error("HMAC key not initialized");
        }
        std::vector<uint8_t> hmac(SHA512_DIGEST_LENGTH);
        unsigned int hmac_len;
        if (HMAC(EVP_sha512(), key_->get_key().data(), key_->size(),
                 data.data(), data.size(), hmac.data(), &hmac_len) == nullptr) {
            throw std::runtime_error("HMAC-SHA512 failed");
        }
        hmac.resize(hmac_len);
        return hmac;
    }
    std::span<const uint8_t> cmac_aes128(
        std::span<const uint8_t> data
    ) const {
        if (!key_) {
            throw std::runtime_error("CMAC key not initialized");
        }
        std::vector<uint8_t> cmac(EVP_MAX_MD_SIZE);
        size_t cmac_len;
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(EVP_MAC_fetch(nullptr, "CMAC", nullptr));
        if (!ctx) {
            throw std::runtime_error("Failed to create CMAC context");
        }
        if (EVP_MAC_init(ctx, key_->get_key().data(), key_->size(), nullptr) != 1) {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize CMAC");
        }
        if (EVP_MAC_update(ctx, data.data(), data.size()) != 1) {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("CMAC update failed");
        }
        if (EVP_MAC_final(ctx, cmac.data(), &cmac_len, cmac.size()) != 1) {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("CMAC finalization failed");
        }
        EVP_MAC_CTX_free(ctx);
        return std::span<const uint8_t>(cmac.data(), cmac_len);
    }
    std::span<const uint8_t> cmac_aes256(
        std::span<const uint8_t> data 
    ) const {
        if (!key_) {
            throw std::runtime_error("CMAC key not initialized");
        }
        std::vector<uint8_t> cmac(EVP_MAX_MD_SIZE);
        size_t cmac_len;
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(EVP_MAC_fetch(nullptr, "CMAC", nullptr));
        if (!ctx) {
            throw std::runtime_error("Failed to create CMAC context");
        }
        if (EVP_MAC_init(ctx, key_->get_key().data(), key_->size(), nullptr) != 1) {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize CMAC");
        }
        if (EVP_MAC_update(ctx, data.data(), data.size()) != 1) {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("CMAC update failed");
        }
        if (EVP_MAC_final(ctx, cmac.data(), &cmac_len, cmac.size()) != 1) {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("CMAC finalization failed");
        }
        EVP_MAC_CTX_free(ctx);
        return std::span<const uint8_t>(cmac.data(), cmac_len);
    }
};
class CompressionAlgorithm {
public:
    static std::shared_ptr<goldenhash::GoldenHash> hash;
    virtual ~CompressionAlgorithm() = default;
    [[nodiscard]] virtual size_t max_compressed_size(size_t uncompressed_size) const noexcept = 0;
    [[nodiscard]] virtual result<size_t> compress(std::span<const std::byte> input, std::span<std::byte> output) noexcept = 0;
    [[nodiscard]] virtual result<size_t> decompress(std::span<const std::byte> input, std::span<std::byte> output) noexcept = 0;
};
class lz4 final : public CompressionAlgorithm {
public:
    static constexpr size_t MIN_MATCH = 4;          // Minimum match length
    static constexpr size_t MAX_DISTANCE = 65535;   // Maximum offset (16-bit)
    static constexpr size_t HASH_TABLE_SIZE = 12415; // Hash table size (12-bit)
    static constexpr size_t ML_BITS = 4;            // Match length bits in token
    static constexpr size_t ML_MASK = (1U << ML_BITS) - 1;
    static constexpr size_t RUN_BITS = 8 - ML_BITS; // Literal length bits
    static constexpr size_t RUN_MASK = (1U << RUN_BITS) - 1;
    static constexpr uint8_t LAST_LITERAL_SIZE = 5;  // Minimum end literals
    static constexpr uint8_t MFLIMIT = 12;           // Minimum input for match
    lz4() noexcept = default;
    ~lz4() override = default;
    [[nodiscard]] size_t max_compressed_size(size_t uncompressed_size) const noexcept override;
    [[nodiscard]] result<size_t> compress(std::span<const std::byte> input, std::span<std::byte> output) noexcept override;
    [[nodiscard]] result<size_t> decompress(std::span<const std::byte> input, std::span<std::byte> output) noexcept override;
    [[nodiscard]] result<size_t> compress_hc(std::span<const std::byte> input, std::span<std::byte> output) noexcept;
    [[nodiscard]] result<size_t> compress_fast(std::span<const std::byte> input, std::span<std::byte> output, int acceleration = 1) noexcept;
private:
    [[nodiscard]] static uint32_t read32(const uint8_t* ptr) noexcept {
        uint32_t val;
        std::memcpy(&val, ptr, sizeof(val));
        #ifdef __BIG_ENDIAN__
            val = __builtin_bswap32(val);
        #endif
        return val;
    }
    [[nodiscard]] static uint16_t read16(const uint8_t* ptr) noexcept {
        uint16_t val;
        std::memcpy(&val, ptr, sizeof(val));
        #ifdef __BIG_ENDIAN__
            val = __builtin_bswap16(val);
        #endif
        return val;
    }
    static void write16(uint8_t* ptr, uint16_t val) noexcept {
        #ifdef __BIG_ENDIAN__
            val = __builtin_bswap16(val);
        #endif
        std::memcpy(ptr, &val, sizeof(val));
    }
    [[nodiscard]] static size_t count_match(
        const uint8_t* pIn,
        const uint8_t* pMatch,
        const uint8_t* pInLimit
    ) noexcept;
    static uint8_t* write_length(
        uint8_t* op,
        size_t length,
        uint8_t* token,
        bool is_literal
    ) noexcept;
    static void wild_copy(uint8_t* dst, const uint8_t* src, uint8_t* dst_end) noexcept;
};
class lz4_frame {
public:
    static constexpr uint32_t MAGIC = 0x184D2204;  // LZ4 frame magic number
    struct frame_descriptor {
        bool content_checksum;
        bool content_size;
        bool block_checksum;
        bool block_independence;
        uint32_t max_block_size;
        frame_descriptor() 
            : content_checksum(false)
            , content_size(false)
            , block_checksum(false)
            , block_independence(true)
            , max_block_size(65536) {}
    };
    [[nodiscard]] static result<std::vector<std::byte>> compress_frame(std::span<const std::byte> input, const frame_descriptor& desc = {}) noexcept;
    [[nodiscard]] static result<std::vector<std::byte>> decompress_frame(std::span<const std::byte> input) noexcept;
};
template<typename T>
concept HasEncryptedSize = requires(const T& t) {
    { t.encrypted_size() } -> std::convertible_to<size_t>;
};
template<typename T>
concept HasEncrypt = requires(T& t, std::span<std::byte> buffer, std::span<const std::byte, 32> key) {
    { t.encrypt(buffer, key) } -> std::convertible_to<size_t>;
};
template<typename T>
concept HasDecrypt = requires(T& t, std::span<const std::byte> data, std::span<const std::byte, 32> key) {
    { t.decrypt(data, key) } -> std::convertible_to<size_t>;
};
enum class WireType : uint8_t {
    VARINT = 0,
    FIXED64 = 1,
    BYTES = 2,
    START_GROUP = 3,
    END_GROUP = 4,
    FIXED32 = 5
};
class predictor {
public:
    virtual ~predictor() = default;
    [[nodiscard]] virtual uint64_t predict() const noexcept = 0;
    virtual void update(uint64_t actual) noexcept = 0;
};
class fcm_predictor final : public predictor {
public:
    explicit fcm_predictor(size_t table_size) noexcept
        : table_(table_size, 0)
        , size_mask_(table_size - 1)
        , last_hash_(0) {}
    [[nodiscard]] uint64_t predict() const noexcept override {
        return table_[last_hash_];
    }
    void update(uint64_t actual) noexcept override {
        table_[last_hash_] = actual;
        last_hash_ = hash(actual);
    }
private:
    [[nodiscard]] uint64_t hash(uint64_t actual) const noexcept {
        return ((last_hash_ << 6) ^ (actual >> 48)) & size_mask_;
    }
    std::vector<uint64_t> table_;
    uint64_t size_mask_;
    uint64_t last_hash_;
};
enum class fpc_compression_level : uint8_t {
    DEFAULT = 10,
    MIN = 1,
    MAX = 32
};
class dfcm_predictor final : public predictor {
public:
    explicit dfcm_predictor(size_t table_size) noexcept
        : table_(table_size, 0)
        , size_mask_(table_size - 1)
        , last_hash_(0)
        , last_value_(0) {}
    [[nodiscard]] uint64_t predict() const noexcept override {
        return table_[last_hash_] + last_value_;
    }
    void update(uint64_t actual) noexcept override {
        table_[last_hash_] = actual - last_value_;
        last_hash_ = hash(actual);
        last_value_ = actual;
    }
private:
    [[nodiscard]] uint64_t hash(uint64_t actual) const noexcept {
        return ((last_hash_ << 2) ^ ((actual - last_value_) >> 40)) & size_mask_;
    }
    std::vector<uint64_t> table_;
    uint64_t size_mask_;
    uint64_t last_hash_;
    uint64_t last_value_;
};
class fpc_writer {
public:
    static constexpr size_t MAX_RECORDS_PER_BLOCK = 32768;
    static constexpr size_t BLOCK_HEADER_SIZE = 6;
    explicit fpc_writer(std::vector<uint8_t>& output) noexcept
        : fpc_writer(output, fpc_compression_level::DEFAULT) {}
    fpc_writer(std::vector<uint8_t>& output, fpc_compression_level level) noexcept;
    void write_float(double value) noexcept;
    void write_floats(std::span<const double> values) noexcept;
    void flush() noexcept;
    [[nodiscard]] size_t bytes_written() const noexcept { return bytes_written_; }
private:
    void write_header() noexcept;
    void encode_value(uint64_t value) noexcept;
    void flush_block() noexcept;
    [[nodiscard]] static uint8_t count_leading_zero_bytes(uint64_t value) noexcept;
    std::vector<uint8_t>& output_;
    uint8_t compression_level_;
    bool header_written_ = false;
    std::unique_ptr<fcm_predictor> fcm_;
    std::unique_ptr<dfcm_predictor> dfcm_;
    std::vector<uint8_t> headers_;
    std::vector<uint8_t> values_;
    uint64_t last_value_ = 0;
    size_t record_count_ = 0;
    size_t bytes_written_ = 0;
};
class fpc_reader {
public:
    static constexpr size_t BLOCK_HEADER_SIZE = 6;
public:
    explicit fpc_reader(std::span<const uint8_t> input) noexcept;
    [[nodiscard]] std::optional<double> read_float() noexcept;
    size_t read_floats(std::span<double> values) noexcept;
    [[nodiscard]] bool has_data() const noexcept { 
        return (block_pos_ < block_values_.size()) || (pos_ < input_.size()); 
    }
private:
    bool read_header() noexcept;
    bool read_block() noexcept;
    [[nodiscard]] std::optional<uint64_t> decode_next_value() noexcept;
    std::span<const uint8_t> input_;
    size_t pos_ = 0;
    uint8_t compression_level_ = 0;
    std::unique_ptr<fcm_predictor> fcm_;
    std::unique_ptr<dfcm_predictor> dfcm_;
    std::vector<uint64_t> block_values_;
    size_t block_pos_ = 0;
};
[[nodiscard]] std::vector<uint8_t> fpc_compress(
    std::span<const double> input,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept;
size_t fpc_decompress(
    std::span<const uint8_t> input,
    std::span<double> output
) noexcept;
[[nodiscard]] size_t fpc_max_decompressed_size(std::span<const uint8_t> input) noexcept;

// Template overloads for multi-dimensional arrays
template<typename T>
requires std::floating_point<T>
[[nodiscard]] std::vector<uint8_t> fpc_compress(
    std::span<const T> input,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept {
    // Convert to double if needed
    if constexpr (std::is_same_v<T, double>) {
        return fpc_compress(std::span<const double>(input.data(), input.size()), level);
    } else {
        std::vector<double> doubles;
        doubles.reserve(input.size());
        for (const auto& val : input) {
            doubles.push_back(static_cast<double>(val));
        }
        return fpc_compress(std::span<const double>(doubles.data(), doubles.size()), level);
    }
}

// Support for 2D arrays (matrices)
template<typename T>
requires std::floating_point<T>
[[nodiscard]] std::vector<uint8_t> fpc_compress_2d(
    std::span<const T> input,
    [[maybe_unused]] size_t rows,
    [[maybe_unused]] size_t cols,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept {
    // Flatten and compress
    return fpc_compress(input, level);
}

// Support for 3D arrays (tensors)
template<typename T>
requires std::floating_point<T>
[[nodiscard]] std::vector<uint8_t> fpc_compress_3d(
    std::span<const T> input,
    [[maybe_unused]] size_t dim1,
    [[maybe_unused]] size_t dim2,
    [[maybe_unused]] size_t dim3,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept {
    // Flatten and compress
    return fpc_compress(input, level);
}

// Support for std::array
template<typename T, size_t N>
requires std::floating_point<T>
[[nodiscard]] std::vector<uint8_t> fpc_compress(
    const std::array<T, N>& input,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept {
    return fpc_compress(std::span<const T>(input.data(), N), level);
}

// Support for std::vector
template<typename T>
requires std::floating_point<T>
[[nodiscard]] std::vector<uint8_t> fpc_compress(
    const std::vector<T>& input,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept {
    return fpc_compress(std::span<const T>(input.data(), input.size()), level);
}

// Support for nested vectors (2D)
template<typename T>
requires std::floating_point<T>
[[nodiscard]] std::vector<uint8_t> fpc_compress(
    const std::vector<std::vector<T>>& input,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept {
    // Flatten the 2D vector
    std::vector<T> flattened;
    size_t total_size = 0;
    for (const auto& row : input) {
        total_size += row.size();
    }
    flattened.reserve(total_size);
    
    for (const auto& row : input) {
        flattened.insert(flattened.end(), row.begin(), row.end());
    }
    
    return fpc_compress(std::span<const T>(flattened.data(), flattened.size()), level);
}

// Decompression templates
template<typename T>
requires std::floating_point<T>
size_t fpc_decompress(
    std::span<const uint8_t> input,
    std::span<T> output
) noexcept {
    if constexpr (std::is_same_v<T, double>) {
        return fpc_decompress(input, std::span<double>(output.data(), output.size()));
    } else {
        // Decompress to temporary double buffer
        std::vector<double> doubles(output.size());
        size_t decompressed = fpc_decompress(input, std::span<double>(doubles.data(), doubles.size()));
        
        // Convert back to original type
        for (size_t i = 0; i < decompressed; ++i) {
            output[i] = static_cast<T>(doubles[i]);
        }
        return decompressed;
    }
}

// Helper struct for tensor metadata
struct fpc_tensor_header {
    uint32_t rank;           // Number of dimensions
    uint32_t total_elements; // Total number of elements
    std::array<uint32_t, 8> dimensions; // Up to 8 dimensions
};

// Compress a tensor with metadata
template<typename T>
requires std::floating_point<T>
[[nodiscard]] std::vector<uint8_t> fpc_compress_tensor(
    std::span<const T> data,
    std::span<const size_t> dimensions,
    fpc_compression_level level = fpc_compression_level::DEFAULT
) noexcept {
    std::vector<uint8_t> result;
    
    // Write header
    fpc_tensor_header header{};
    header.rank = static_cast<uint32_t>(dimensions.size());
    header.total_elements = 1;
    
    for (size_t i = 0; i < dimensions.size() && i < 8; ++i) {
        header.dimensions[i] = static_cast<uint32_t>(dimensions[i]);
        header.total_elements *= header.dimensions[i];
    }
    
    // Reserve space for header + compressed data
    result.resize(sizeof(fpc_tensor_header));
    std::memcpy(result.data(), &header, sizeof(fpc_tensor_header));
    
    // Compress the data
    auto compressed = fpc_compress(data, level);
    result.insert(result.end(), compressed.begin(), compressed.end());
    
    return result;
}

// Decompress a tensor with metadata
template<typename T>
requires std::floating_point<T>
[[nodiscard]] std::optional<std::pair<std::vector<T>, std::vector<size_t>>> fpc_decompress_tensor(
    std::span<const uint8_t> input
) noexcept {
    if (input.size() < sizeof(fpc_tensor_header)) {
        return std::nullopt;
    }
    
    // Read header
    fpc_tensor_header header;
    std::memcpy(&header, input.data(), sizeof(fpc_tensor_header));
    
    // Extract dimensions
    std::vector<size_t> dimensions;
    dimensions.reserve(header.rank);
    for (uint32_t i = 0; i < header.rank; ++i) {
        dimensions.push_back(header.dimensions[i]);
    }
    
    // Allocate output buffer
    std::vector<T> output(header.total_elements);
    
    // Decompress data
    auto compressed_data = input.subspan(sizeof(fpc_tensor_header));
    size_t decompressed = fpc_decompress(compressed_data, std::span<T>(output.data(), output.size()));
    
    if (decompressed != header.total_elements) {
        return std::nullopt;
    }
    
    return std::make_pair(std::move(output), std::move(dimensions));
}

// Convenience function for common matrix operations
template<typename T>
requires std::floating_point<T>
struct fpc_matrix_view {
    std::span<const T> data;
    size_t rows;
    size_t cols;
    
    [[nodiscard]] std::vector<uint8_t> compress(
        fpc_compression_level level = fpc_compression_level::DEFAULT
    ) const noexcept {
        std::array<size_t, 2> dims = {rows, cols};
        return fpc_compress_tensor(data, dims, level);
    }
};

enum class predictor_type : uint8_t {
    FCM = 0,   // Finite Context Method
    DFCM = 1   // Differential Finite Context Method
};
struct pair_header {
    uint8_t h1_len;
    predictor_type h1_type;
    uint8_t h2_len;
    predictor_type h2_type;
    [[nodiscard]] constexpr uint8_t encode() const noexcept {
        uint8_t h1_bits = (static_cast<uint8_t>(h1_type) << 3) | h1_len;
        uint8_t h2_bits = (static_cast<uint8_t>(h2_type) << 3) | h2_len;
        return (h1_bits << 4) | h2_bits;
    }
    static constexpr pair_header decode(uint8_t byte) noexcept {
        pair_header h;
        uint8_t h1_bits = (byte >> 4) & 0x0F;
        h.h1_type = static_cast<predictor_type>((h1_bits >> 3) & 1);
        h.h1_len = h1_bits & 0x07;
        uint8_t h2_bits = byte & 0x0F;
        h.h2_type = static_cast<predictor_type>((h2_bits >> 3) & 1);
        h.h2_len = h2_bits & 0x07;
        if (h.h1_len >= 4) h.h1_len++;
        if (h.h2_len >= 4) h.h2_len++;
        return h;
    }
};
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline static std::string base64_encode(const std::span<uint8_t>& bytes_to_encode) {
    std::string ret;
    int i = 0;
    int j = 0;
    uint8_t bytes_3[3];
    uint8_t bytes_4[4];
    auto in_len = static_cast<unsigned int>(bytes_to_encode.size());
    while (in_len--) {
        bytes_3[i++] = bytes_to_encode.data()[bytes_to_encode.size() - in_len - 1];
        if (i == 3) {
            bytes_4[0] = (bytes_3[0] & 0xfc) >> 2;
            bytes_4[1] = ((bytes_3[0] & 0x03) << 4) + ((bytes_3[1] & 0xf0) >> 4);
            bytes_4[2] = ((bytes_3[1] & 0x0f) << 2) + ((bytes_3[2] & 0xc0) >> 6);
            bytes_4[3] = bytes_3[2] & 0x3f;
            for(i = 0; (i <4) ; i++) ret += base64_chars[bytes_4[i]];
            i = 0;
        }
    }
    if (i) {
        for(j = i; j < 3; j++)
        bytes_3[j] = '\0';
        bytes_4[0] = ( bytes_3[0] & 0xfc) >> 2;
        bytes_4[1] = ((bytes_3[0] & 0x03) << 4) + ((bytes_3[1] & 0xf0) >> 4);
        bytes_4[2] = ((bytes_3[1] & 0x0f) << 2) + ((bytes_3[2] & 0xc0) >> 6);
        for (j = 0; (j < i + 1); j++) ret += base64_chars[bytes_4[j]];
        while ((i++ < 3)) ret += '=';
    }
    return ret;
}
inline static std::string base64_decode(std::string_view encoded_string) {
    size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char bytes_4[4], bytes_3[3];
    std::string ret;
    while (in_len-- && ( encoded_string[in_] != '=')) {
        bytes_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++) bytes_4[i] = base64_chars.find(bytes_4[i]) & 0xff;
            bytes_3[0] = ( bytes_4[0] << 2) + ((bytes_4[1] & 0x30) >> 4);
            bytes_3[1] = ((bytes_4[1] & 0xf) << 4) + ((bytes_4[2] & 0x3c) >> 2);
            bytes_3[2] = ((bytes_4[2] & 0x3) << 6) +   bytes_4[3];
            for (i = 0; (i < 3); i++) ret += bytes_3[i];
            i = 0;
        }
    }
    if (i) {
        for (j = 0; j < i; j++)
        bytes_4[j] = base64_chars.find(bytes_4[j]) & 0xff;
        bytes_3[0] = (bytes_4[0] << 2) + ((bytes_4[1] & 0x30) >> 4);
        bytes_3[1] = ((bytes_4[1] & 0xf) << 4) + ((bytes_4[2] & 0x3c) >> 2);
        for (j = 0; (j < i - 1); j++) ret += bytes_3[j];
    }
    return ret;
}
}

#endif // PSYFER_MAIN_HPP