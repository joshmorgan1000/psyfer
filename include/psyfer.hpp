#pragma once
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
namespace psyfer {
constexpr uint32_t VERSION_MAJOR = 1;
constexpr uint32_t VERSION_MINOR = 0;
constexpr uint32_t VERSION_PATCH = 0;
}
template<typename T>
concept HasEncryptedSize = requires(const T& t) {
    { t.encrypted_size() } -> std::convertible_to<size_t>;
};
template<typename T>
concept HasDecrypt = requires(std::span<const std::byte> src, T* target, std::span<const std::byte> key) {
    { T::decrypt(src, target, key) } -> std::convertible_to<size_t>;
};
namespace std {
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
getGlobalContext().currently_serving.notify_all(); } }
namespace psyfer {
namespace config {
    inline std::atomic<bool> use_software_only_for_encryption{false};
    inline void enable_software_only() noexcept {
        use_software_only_for_encryption.store(true);
    }
    inline void disable_software_only() noexcept {
        use_software_only_for_encryption.store(false);
    }
    [[nodiscard]] inline bool is_software_only() noexcept {
        return use_software_only_for_encryption.load();
    }
}
enum class error_code : int32_t {
    success = 0,
    invalid_argument,
    invalid_key_size,
    invalid_nonce_size,
    invalid_tag_size,
    invalid_buffer_size,
    encryption_failed,
    decryption_failed,
    authentication_failed,
    compression_failed,
    decompression_failed,
    hash_mismatch,
    memory_allocation_failed,
    not_implemented,
    crypto_error,
    buffer_too_small,
    unknown_error
};
class error_category_impl final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "psyfer"; }
    [[nodiscard]] std::string message(int ev) const override;
};
[[nodiscard]] const std::error_category& get_error_category() noexcept;
[[nodiscard]] inline std::error_code make_error_code(error_code e) noexcept {
    return {static_cast<int>(e), get_error_category()};
}
template<typename T>
using result = std::expected<T, std::error_code>;
namespace key_sizes {
    constexpr size_t AES256 = 32;
    constexpr size_t CHACHA20 = 32;
    constexpr size_t X25519_PRIVATE = 32;
    constexpr size_t X25519_PUBLIC = 32;
    constexpr size_t BLAKE3 = 32;
}
namespace nonce_sizes {
    constexpr size_t AES256_GCM = 12;
    constexpr size_t CHACHA20_POLY1305 = 12;
}
namespace tag_sizes {
    constexpr size_t AES256_GCM = 16;
    constexpr size_t CHACHA20_POLY1305 = 16;
}
template<typename T>
concept byte_container = requires(T t) {
    { t.data() } -> std::convertible_to<const std::byte*>;
    { t.size() } -> std::convertible_to<std::size_t>;
};
template<typename T>
concept mutable_byte_container = byte_container<T> && requires(T t) {
    { t.data() } -> std::convertible_to<std::byte*>;
};
class hash_algorithm {
public:
    virtual ~hash_algorithm() = default;
    [[nodiscard]] virtual size_t output_size() const noexcept = 0;
    virtual void update(std::span<const std::byte> data) noexcept = 0;
    virtual void finalize(std::span<std::byte> output) noexcept = 0;
    virtual void reset() noexcept = 0;
};
class encryption_algorithm {
public:
    virtual ~encryption_algorithm() = default;
    [[nodiscard]] virtual size_t key_size() const noexcept = 0;
    [[nodiscard]] virtual size_t nonce_size() const noexcept = 0;
    [[nodiscard]] virtual size_t tag_size() const noexcept = 0;
    [[nodiscard]] virtual std::error_code encrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept = 0;
    [[nodiscard]] virtual std::error_code decrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<const std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept = 0;
};
class compression_algorithm {
public:
    virtual ~compression_algorithm() = default;
    [[nodiscard]] virtual size_t max_compressed_size(size_t uncompressed_size) const noexcept = 0;
    [[nodiscard]] virtual result<size_t> compress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept = 0;
    [[nodiscard]] virtual result<size_t> decompress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept = 0;
};
}
template<>
struct std::is_error_code_enum<psyfer::error_code> : std::true_type {};
namespace psyfer::hash {
class sha256 final : public hash_algorithm {
public:
    sha256() noexcept;
    ~sha256() override;
    [[nodiscard]] size_t output_size() const noexcept override { return 32; }
    void update(std::span<const std::byte> data) noexcept override;
    void finalize(std::span<std::byte> output) noexcept override;
    void reset() noexcept override;
    static void hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept;
private:
    class impl;
    std::unique_ptr<impl> pimpl;
};
class sha512 final : public hash_algorithm {
public:
    sha512() noexcept;
    ~sha512() override;
    [[nodiscard]] size_t output_size() const noexcept override { return 64; }
    void update(std::span<const std::byte> data) noexcept override;
    void finalize(std::span<std::byte> output) noexcept override;
    void reset() noexcept override;
    static void hash(std::span<const std::byte> input, std::span<std::byte> output) noexcept;
private:
    class impl;
    std::unique_ptr<impl> pimpl;
};
class hmac_sha256 final : public hash_algorithm {
public:
    explicit hmac_sha256(std::span<const std::byte> key) noexcept;
    ~hmac_sha256() override;
    [[nodiscard]] size_t output_size() const noexcept override { return 32; }
    void update(std::span<const std::byte> data) noexcept override;
    void finalize(std::span<std::byte> output) noexcept override;
    void reset() noexcept override;
    static void hmac(
        std::span<const std::byte> key,
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept;
private:
    class impl;
    std::unique_ptr<impl> pimpl;
};
class hmac_sha512 final : public hash_algorithm {
public:
    explicit hmac_sha512(std::span<const std::byte> key) noexcept;
    ~hmac_sha512() override;
    [[nodiscard]] size_t output_size() const noexcept override { return 64; }
    void update(std::span<const std::byte> data) noexcept override;
    void finalize(std::span<std::byte> output) noexcept override;
    void reset() noexcept override;
    static void hmac(
        std::span<const std::byte> key,
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept;
private:
    class impl;
    std::unique_ptr<impl> pimpl;
};
class xxhash3_24 {
public:
    static constexpr size_t HASH_SIZE = 3; // 24 bits
    [[nodiscard]] static uint32_t hash( std::span<const std::byte> data,
        uint64_t seed = 0 ) noexcept;
    [[nodiscard]] static uint32_t hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
};
class xxhash3_32 {
public:
    static constexpr size_t HASH_SIZE = 4; // 32 bits
    [[nodiscard]] static uint32_t hash(
        std::span<const std::byte> data,
        uint64_t seed = 0
    ) noexcept;
    [[nodiscard]] static uint32_t hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
};
class xxhash3_64 {
public:
    static constexpr size_t HASH_SIZE = 8; // 64 bits
    [[nodiscard]] static uint64_t hash(
        std::span<const std::byte> data,
        uint64_t seed = 0
    ) noexcept;
    [[nodiscard]] static uint64_t hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
    class hasher {
    public:
        explicit hasher(uint64_t seed = 0) noexcept;
        hasher& update(std::span<const std::byte> data) noexcept;
        hasher& update(std::string_view str) noexcept {
            return update(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(str.data()),
                    str.size()
                )
            );
        }
        [[nodiscard]] uint64_t finalize() noexcept;
        void reset(uint64_t seed = 0) noexcept;
    private:
        static constexpr size_t BUFFER_SIZE = 256;
        static constexpr size_t ACC_NB = 8;
        alignas(32) std::array<uint64_t, ACC_NB> acc_;
        alignas(32) std::array<std::byte, BUFFER_SIZE> buffer_;
        size_t buffer_size_;
        size_t total_len_;
        uint64_t seed_;
    };
};
class xxhash3_128 {
public:
    static constexpr size_t HASH_SIZE = 16; // 128 bits
    struct hash128 {
        uint64_t low;
        uint64_t high;
        bool operator==(const hash128& other) const noexcept {
            return low == other.low && high == other.high;
        }
        bool operator!=(const hash128& other) const noexcept {
            return !(*this == other);
        }
    };
    [[nodiscard]] static hash128 hash(
        std::span<const std::byte> data,
        uint64_t seed = 0
    ) noexcept;
    [[nodiscard]] static hash128 hash(
        std::string_view str,
        uint64_t seed = 0
    ) noexcept {
        return hash(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(str.data()),
                str.size()
            ),
            seed
        );
    }
    class hasher {
    public:
        explicit hasher(uint64_t seed = 0) noexcept;
        hasher& update(std::span<const std::byte> data) noexcept;
        hasher& update(std::string_view str) noexcept {
            return update(
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(str.data()),
                    str.size()
                )
            );
        }
        [[nodiscard]] hash128 finalize() noexcept;
        void reset(uint64_t seed = 0) noexcept;
    private:
        static constexpr size_t BUFFER_SIZE = 256;
        static constexpr size_t ACC_NB = 8;
        alignas(32) std::array<uint64_t, ACC_NB> acc_;
        alignas(32) std::array<std::byte, BUFFER_SIZE> buffer_;
        size_t buffer_size_;
        size_t total_len_;
        uint64_t seed_;
    };
};
using xxh3_24 = xxhash3_24;
using xxh3_32 = xxhash3_32;
using xxh3_64 = xxhash3_64;
using xxh3_128 = xxhash3_128;
}
namespace psyfer::crypto {
[[nodiscard]] bool aes_ni_available() noexcept;
class aes256 {
public:
    static constexpr size_t BLOCK_SIZE = 16;  // 128 bits
    static constexpr size_t KEY_SIZE = 32;    // 256 bits
    static constexpr size_t ROUNDS = 14;      // AES-256 uses 14 rounds
    
    /**
     * @brief Check if hardware acceleration is available
     * @return true if AES-NI, ARM crypto, or CommonCrypto is available
     */
    static bool hardware_available() noexcept;
    
    explicit aes256(std::span<const std::byte, KEY_SIZE> key) noexcept;
    void encrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept;
    void decrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept;
private:
    alignas(16) std::array<std::byte, (ROUNDS + 1) * BLOCK_SIZE> round_keys{};
    bool use_hw_acceleration = false;
    void key_expansion(std::span<const std::byte, KEY_SIZE> key) noexcept;
    void encrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept;
    void decrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept;
};
class aes256_gcm final : public encryption_algorithm {
public:
    static constexpr size_t KEY_SIZE = 32;    // 256 bits
    static constexpr size_t NONCE_SIZE = 12;  // 96 bits (recommended)
    static constexpr size_t TAG_SIZE = 16;    // 128 bits
    aes256_gcm() noexcept = default;
    [[nodiscard]] size_t key_size() const noexcept override { return KEY_SIZE; }
    [[nodiscard]] size_t nonce_size() const noexcept override { return NONCE_SIZE; }
    [[nodiscard]] size_t tag_size() const noexcept override { return TAG_SIZE; }
    [[nodiscard]] std::error_code encrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept override;
    [[nodiscard]] std::error_code decrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<const std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept override;
    static std::error_code encrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
    static std::error_code decrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<const std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
private:
    static void ghash(
        std::span<std::byte, 16> output,
        std::span<const std::byte, 16> h,
        std::span<const std::byte> data
    ) noexcept;
    static void increment_counter(std::span<std::byte, 16> counter) noexcept;
}; }
namespace psyfer::mac {
template<size_t KeySize>
class aes_cmac {
public:
    static constexpr size_t KEY_SIZE = KeySize;
    static constexpr size_t MAC_SIZE = 16;  // Always 128 bits regardless of key size
    static constexpr size_t BLOCK_SIZE = 16;
    explicit aes_cmac(std::span<const std::byte, KEY_SIZE> key) noexcept;
    ~aes_cmac() noexcept;
    void update(std::span<const std::byte> data) noexcept;
    void finalize(std::span<std::byte, MAC_SIZE> mac) noexcept;
    void reset() noexcept;
    static void compute(
        std::span<const std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<std::byte, MAC_SIZE> mac
    ) noexcept;
    [[nodiscard]] static bool verify(
        std::span<const std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, MAC_SIZE> mac
    ) noexcept;
private:
    struct cipher_impl;
    std::unique_ptr<cipher_impl> cipher;
    alignas(16) std::array<std::byte, BLOCK_SIZE> k1{};  // First subkey
    alignas(16) std::array<std::byte, BLOCK_SIZE> k2{};  // Second subkey
    alignas(16) std::array<std::byte, BLOCK_SIZE> state{};  // Current state
    alignas(16) std::array<std::byte, BLOCK_SIZE> buffer{};  // Partial block buffer
    size_t buffer_pos = 0;
    void generate_subkeys() noexcept;
    void process_block(std::span<const std::byte, BLOCK_SIZE> block) noexcept;
    static void left_shift_one(std::span<std::byte, BLOCK_SIZE> data) noexcept;
};
using aes_cmac_128 = aes_cmac<16>;
using aes_cmac_256 = aes_cmac<32>;
using cmac128 = aes_cmac_128;
using cmac256 = aes_cmac_256;
}
namespace psyfer::utils {
class secure_random {
public:
    [[nodiscard]] static std::error_code generate(std::span<std::byte> buffer) noexcept;
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
    template<size_t N>
    [[nodiscard]] static result<std::array<std::byte, N>> generate_array() noexcept {
        std::array<std::byte, N> arr;
        auto ec = generate(arr);
        if (ec) {
            return std::unexpected(ec);
        }
        return arr;
    }
    template<size_t N>
    [[nodiscard]] static result<std::array<std::byte, N>> generate_key() noexcept {
        return generate_array<N>();
    }
    template<size_t N>
    [[nodiscard]] static result<std::array<std::byte, N>> generate_nonce() noexcept {
        return generate_array<N>();
    }
private:
    secure_random() = delete;  // Static class only
};
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
template<size_t N>
class secure_buffer {
public:
    static constexpr size_t size = N;
    secure_buffer() noexcept;
    ~secure_buffer() noexcept;
    secure_buffer(const secure_buffer&) = delete;
    secure_buffer& operator=(const secure_buffer&) = delete;
    secure_buffer(secure_buffer&& other) noexcept;
    secure_buffer& operator=(secure_buffer&& other) noexcept;
    [[nodiscard]] std::span<std::byte, N> span() noexcept {
        return std::span<std::byte, N>(data_, N);
    }
    [[nodiscard]] std::span<const std::byte, N> span() const noexcept {
        return std::span<const std::byte, N>(data_, N);
    }
    [[nodiscard]] std::byte* data() noexcept { return data_; }
    [[nodiscard]] const std::byte* data() const noexcept { return data_; }
    void clear() noexcept;
    void fill(std::span<const std::byte, N> source) noexcept;
private:
    alignas(16) std::byte data_[N];
    bool locked_ = false;
    void lock_memory() noexcept;
    void unlock_memory() noexcept;
};
using secure_string = std::basic_string<char, std::char_traits<char>, 
                                        secure_allocator<char>>;
template<typename T>
using secure_vector = std::vector<T, secure_allocator<T>>;
template<typename T, size_t N>
class secure_array : public std::array<T, N> {
public:
    ~secure_array() { secure_clear(this->data(), N * sizeof(T)); }
    using std::array<T, N>::array;
};
void secure_clear(void* ptr, size_t size) noexcept;
[[nodiscard]] bool secure_compare(
    const void* a, 
    const void* b, 
    size_t size
) noexcept;
template<size_t KeySize>
class secure_key {
public:
    static constexpr size_t size = KeySize;
    using key_type = secure_buffer<KeySize>;
    secure_key() noexcept = default;
    [[nodiscard]] static result<secure_key> generate() noexcept {
        secure_key key;
        auto ec = secure_random::generate(key.key_.span());
        if (ec) return std::unexpected(ec);
        key.created_at_ = std::chrono::steady_clock::now();
        return key;
    }
    [[nodiscard]] static secure_key from_bytes(std::span<const std::byte, KeySize> key_data) noexcept {
        secure_key key;
        key.key_.fill(key_data);
        key.created_at_ = std::chrono::steady_clock::now();
        return key;
    }
    [[nodiscard]] static result<secure_key> from_password(
        std::string_view password,
        std::span<const std::byte> salt,
        uint32_t iterations = 100000
    ) noexcept;
    [[nodiscard]] std::span<const std::byte, KeySize> span() const noexcept {
        return key_.span();
    }
    [[nodiscard]] const std::byte* data() const noexcept {
        return key_.data();
    }
    [[nodiscard]] bool is_empty() const noexcept {
        for (auto b : key_.span()) {
            if (b != std::byte{0}) return false;
        }
        return true;
    }
    [[nodiscard]] std::chrono::steady_clock::duration age() const noexcept {
        return std::chrono::steady_clock::now() - created_at_;
    }
    [[nodiscard]] bool should_rotate(std::chrono::steady_clock::duration max_age) const noexcept {
        return age() > max_age;
    }
    void clear() noexcept {
        key_.clear();
        created_at_ = {};
    }
    [[nodiscard]] bool operator==(const secure_key& other) const noexcept {
        return secure_compare(key_.data(), other.key_.data(), KeySize);
    }
    [[nodiscard]] result<secure_vector<std::byte>> export_protected(
        std::span<const std::byte, 32> protection_key
    ) const noexcept;
    [[nodiscard]] static result<secure_key> import_protected(
        std::span<const std::byte> encrypted_data,
        std::span<const std::byte, 32> protection_key
    ) noexcept;
private:
    key_type key_;
    std::chrono::steady_clock::time_point created_at_;
};
using secure_key_128 = secure_key<16>;   // 128-bit keys
using secure_key_192 = secure_key<24>;   // 192-bit keys
using secure_key_256 = secure_key<32>;   // 256-bit keys
using secure_key_512 = secure_key<64>;   // 512-bit keys
using aes256_key = secure_key<32>;
using chacha20_key = secure_key<32>;
using x25519_private_key = secure_key<32>;
using x25519_key = x25519_private_key;  // Alias for convenience
using blake3_key = secure_key<32>;
} // namespace psyfer::utils
namespace psyfer::kdf {
class hkdf {
public:
    [[nodiscard]] static std::error_code derive_sha256(
        std::span<const std::byte> ikm,
        std::span<const std::byte> salt,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;
    [[nodiscard]] static std::error_code derive_sha512(
        std::span<const std::byte> ikm,
        std::span<const std::byte> salt,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;
    static void extract_sha256(
        std::span<const std::byte> salt,
        std::span<const std::byte> ikm,
        std::span<std::byte, 32> prk
    ) noexcept;
    static void extract_sha512(
        std::span<const std::byte> salt,
        std::span<const std::byte> ikm,
        std::span<std::byte, 64> prk
    ) noexcept;
    [[nodiscard]] static std::error_code expand_sha256(
        std::span<const std::byte, 32> prk,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;
    [[nodiscard]] static std::error_code expand_sha512(
        std::span<const std::byte, 64> prk,
        std::span<const std::byte> info,
        std::span<std::byte> okm
    ) noexcept;
private:
    static constexpr size_t MAX_OUTPUT_SHA256 = 255 * 32;
    static constexpr size_t MAX_OUTPUT_SHA512 = 255 * 64;
};
} // namespace psyfer::kdf
namespace psyfer::crypto {
class aes128 {
public:
    static constexpr size_t BLOCK_SIZE = 16;  // 128 bits
    static constexpr size_t KEY_SIZE = 16;    // 128 bits
    static constexpr size_t ROUNDS = 10;      // AES-128 uses 10 rounds
    explicit aes128(std::span<const std::byte, KEY_SIZE> key) noexcept;
    void encrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept;
    void decrypt_block(std::span<std::byte, BLOCK_SIZE> block) noexcept;
private:
    alignas(16) std::array<std::byte, (ROUNDS + 1) * BLOCK_SIZE> round_keys{};
    bool use_hw_acceleration = false;
    void key_expansion(std::span<const std::byte, KEY_SIZE> key) noexcept;
    void encrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept;
    void decrypt_block_sw(std::span<std::byte, BLOCK_SIZE> block) noexcept;
};
#ifdef __APPLE__
bool aes128_commoncrypto_available() noexcept;
void aes128_encrypt_block_cc(const uint8_t* key, uint8_t* block) noexcept;
void aes128_decrypt_block_cc(const uint8_t* key, uint8_t* block) noexcept;
#endif
#if defined(__AES__) && (defined(__x86_64__) || defined(__i386__))
void aes128_encrypt_block_ni(const uint8_t* round_keys, uint8_t* block) noexcept;
void aes128_decrypt_block_ni(const uint8_t* round_keys, uint8_t* block) noexcept;
void aes128_key_expansion_ni(const uint8_t* key, uint8_t* round_keys) noexcept;
#endif
class chacha20 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t BLOCK_SIZE = 64;
    static void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept;
    static void generate_block(
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        uint32_t counter,
        std::span<std::byte, BLOCK_SIZE> output
    ) noexcept;
    static void crypt(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        uint32_t counter = 0
    ) noexcept;
private:
    [[nodiscard]] static constexpr uint32_t rotl(uint32_t x, int n) noexcept {
        return (x << n) | (x >> (32 - n));
    }
};
class poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t TAG_SIZE = 16;
    poly1305() noexcept = default;
    void init(std::span<const std::byte, KEY_SIZE> key) noexcept;
    void update(std::span<const std::byte> data) noexcept;
    void finalize(std::span<std::byte, TAG_SIZE> tag) noexcept;
    static void auth(
        std::span<const std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<std::byte, TAG_SIZE> tag
    ) noexcept;
private:
    uint32_t r_[5] = {0};  // Clamped part of key
    uint32_t h_[5] = {0};  // Accumulator
    uint32_t pad_[4] = {0}; // Encrypted nonce
    size_t leftover_ = 0;
    uint8_t buffer_[16] = {0};
    bool finalized_ = false;
    void process_block(const uint8_t* block, bool final = false) noexcept;
};
class chacha20_poly1305 final : public encryption_algorithm {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    [[nodiscard]] size_t key_size() const noexcept override { return KEY_SIZE; }
    [[nodiscard]] size_t nonce_size() const noexcept override { return NONCE_SIZE; }
    [[nodiscard]] size_t tag_size() const noexcept override { return TAG_SIZE; }
    [[nodiscard]] std::error_code encrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept override;
    [[nodiscard]] std::error_code decrypt(
        std::span<std::byte> data,
        std::span<const std::byte> key,
        std::span<const std::byte> nonce,
        std::span<const std::byte> tag,
        std::span<const std::byte> aad = {}
    ) noexcept override;
    [[nodiscard]] static std::error_code encrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
    [[nodiscard]] static std::error_code decrypt_oneshot(
        std::span<std::byte> data,
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<const std::byte, TAG_SIZE> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
private:
    static void generate_poly_key(
        std::span<const std::byte, KEY_SIZE> key,
        std::span<const std::byte, NONCE_SIZE> nonce,
        std::span<std::byte, 32> poly_key
    ) noexcept;
    static void pad16(poly1305& poly, size_t len) noexcept;
};
class ed25519 {
public:
    static constexpr size_t PRIVATE_KEY_SIZE = 32;
    static constexpr size_t PUBLIC_KEY_SIZE = 32;
    static constexpr size_t SIGNATURE_SIZE = 64;
    static constexpr size_t SEED_SIZE = 32;
    struct key_pair {
        std::array<std::byte, PRIVATE_KEY_SIZE> private_key;
        std::array<std::byte, PUBLIC_KEY_SIZE> public_key;
    };
    [[nodiscard]] static result<key_pair> generate_key_pair() noexcept;
    [[nodiscard]] static result<key_pair> key_pair_from_seed(
        std::span<const std::byte, SEED_SIZE> seed
    ) noexcept;
    static void public_key_from_private(
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    [[nodiscard]] static std::error_code sign(
        std::span<const std::byte> message,
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, SIGNATURE_SIZE> signature
    ) noexcept;
    [[nodiscard]] static bool verify(
        std::span<const std::byte> message,
        std::span<const std::byte, SIGNATURE_SIZE> signature,
        std::span<const std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    [[nodiscard]] static std::error_code sign_detached(
        std::span<const std::byte> message,
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, SIGNATURE_SIZE> signature
    ) noexcept;
    [[nodiscard]] static bool verify_detached(
        std::span<const std::byte> message,
        std::span<const std::byte, SIGNATURE_SIZE> signature,
        std::span<const std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    [[nodiscard]] static bool hardware_accelerated() noexcept;
};
class x25519 {
public:
    static constexpr size_t PRIVATE_KEY_SIZE = 32;
    static constexpr size_t PUBLIC_KEY_SIZE = 32;
    static constexpr size_t SHARED_SECRET_SIZE = 32;
    static constexpr std::array<uint8_t, 32> BASEPOINT = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    [[nodiscard]] static std::error_code generate_private_key(
        std::span<std::byte, PRIVATE_KEY_SIZE> private_key
    ) noexcept;
    [[nodiscard]] static std::error_code derive_public_key(
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<std::byte, PUBLIC_KEY_SIZE> public_key
    ) noexcept;
    [[nodiscard]] static std::error_code compute_shared_secret(
        std::span<const std::byte, PRIVATE_KEY_SIZE> private_key,
        std::span<const std::byte, PUBLIC_KEY_SIZE> peer_public_key,
        std::span<std::byte, SHARED_SECRET_SIZE> shared_secret
    ) noexcept;
    struct key_pair {
        std::array<std::byte, PRIVATE_KEY_SIZE> private_key;
        std::array<std::byte, PUBLIC_KEY_SIZE> public_key;
        [[nodiscard]] static std::expected<key_pair, std::error_code> generate() noexcept;
        [[nodiscard]] std::error_code compute_shared_secret(
            std::span<const std::byte, PUBLIC_KEY_SIZE> peer_public_key,
            std::span<std::byte, SHARED_SECRET_SIZE> shared_secret
        ) const noexcept;
    };
    static void scalarmult(
        uint8_t* out,
        const uint8_t* scalar,
        const uint8_t* point
    ) noexcept;
private:
    using fe = std::array<uint64_t, 5>;
    static void fe_frombytes(fe& h, const uint8_t* s) noexcept;
    static void fe_tobytes(uint8_t* s, const fe& h) noexcept;
    static void fe_add(fe& h, const fe& f, const fe& g) noexcept;
    static void fe_sub(fe& h, const fe& f, const fe& g) noexcept;
    static void fe_mul(fe& h, const fe& f, const fe& g) noexcept;
    static void fe_sq(fe& h, const fe& f) noexcept;
    static void fe_mul121666(fe& h, const fe& f) noexcept;
    static void fe_invert(fe& out, const fe& z) noexcept;
    static void fe_cswap(fe& f, fe& g, unsigned int b) noexcept;
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

class lz4 final : public compression_algorithm {
public:
    static constexpr size_t MIN_MATCH = 4;          // Minimum match length
    static constexpr size_t MAX_DISTANCE = 65535;   // Maximum offset (16-bit)
    static constexpr size_t HASH_TABLE_SIZE = 4096; // Hash table size (12-bit)
    static constexpr size_t ML_BITS = 4;            // Match length bits in token
    static constexpr size_t ML_MASK = (1U << ML_BITS) - 1;
    static constexpr size_t RUN_BITS = 8 - ML_BITS; // Literal length bits
    static constexpr size_t RUN_MASK = (1U << RUN_BITS) - 1;
    static constexpr uint8_t LAST_LITERAL_SIZE = 5;  // Minimum end literals
    static constexpr uint8_t MFLIMIT = 12;           // Minimum input for match
    lz4() noexcept = default;
    ~lz4() override = default;
    [[nodiscard]] size_t max_compressed_size(size_t uncompressed_size) const noexcept override;
    [[nodiscard]] result<size_t> compress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept override;
    [[nodiscard]] result<size_t> decompress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept override;
    [[nodiscard]] result<size_t> compress_hc(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept;
    [[nodiscard]] result<size_t> compress_fast(
        std::span<const std::byte> input,
        std::span<std::byte> output,
        int acceleration = 1
    ) noexcept;
private:
    [[nodiscard]] static uint32_t hash4(const uint8_t* ptr, uint32_t h) noexcept {
        // Simple but effective hash function
        return ((read32(ptr) * 2654435761U) >> (32 - h));
    }
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
    [[nodiscard]] static result<std::vector<std::byte>> compress_frame(
        std::span<const std::byte> input,
        const frame_descriptor& desc = {}
    ) noexcept;
    [[nodiscard]] static result<std::vector<std::byte>> decompress_frame(
        std::span<const std::byte> input
    ) noexcept;
};
}
namespace psyfer::serialization {
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

class BufferReader {
public:
    explicit BufferReader(std::span<const std::byte> data) noexcept 
        : data_(data), pos_(0) {}
    
    [[nodiscard]] std::optional<uint32_t> read_u32() noexcept {
        if (pos_ + 4 > data_.size()) return std::nullopt;
        uint32_t val;
        std::memcpy(&val, data_.data() + pos_, 4);
        pos_ += 4;
        return val;
    }
    
    [[nodiscard]] std::optional<uint64_t> read_u64() noexcept {
        if (pos_ + 8 > data_.size()) return std::nullopt;
        uint64_t val;
        std::memcpy(&val, data_.data() + pos_, 8);
        pos_ += 8;
        return val;
    }
    
    [[nodiscard]] std::optional<std::string_view> read_string_field() noexcept {
        auto len = read_u32();
        if (!len || pos_ + *len > data_.size()) return std::nullopt;
        std::string_view str(reinterpret_cast<const char*>(data_.data() + pos_), *len);
        pos_ += *len;
        return str;
    }
    
    [[nodiscard]] std::optional<std::span<const std::byte>> read_bytes(size_t len) noexcept {
        if (pos_ + len > data_.size()) return std::nullopt;
        auto span = data_.subspan(pos_, len);
        pos_ += len;
        return span;
    }
    
    [[nodiscard]] std::optional<std::span<const std::byte>> read_bytes_field() noexcept {
        auto len = read_u32();
        if (!len) return std::nullopt;
        return read_bytes(*len);
    }
    
    [[nodiscard]] size_t position() const noexcept { return pos_; }
    [[nodiscard]] bool has_more() const noexcept { return pos_ < data_.size(); }

private:
    std::span<const std::byte> data_;
    size_t pos_;
};

class BufferWriter {
public:
    explicit BufferWriter(std::vector<std::byte>& buffer) noexcept 
        : buffer_(buffer) {}
    
    void write_u32(uint32_t val) noexcept {
        auto offset = buffer_.size();
        buffer_.resize(offset + 4);
        std::memcpy(buffer_.data() + offset, &val, 4);
    }
    
    void write_u64(uint64_t val) noexcept {
        auto offset = buffer_.size();
        buffer_.resize(offset + 8);
        std::memcpy(buffer_.data() + offset, &val, 8);
    }
    
    void write_field_header(uint32_t field_num, WireType type) noexcept {
        write_u32((field_num << 3) | static_cast<uint32_t>(type));
    }
    
    void write_string(std::string_view str) noexcept {
        write_u32(static_cast<uint32_t>(str.size()));
        auto offset = buffer_.size();
        buffer_.resize(offset + str.size());
        std::memcpy(buffer_.data() + offset, str.data(), str.size());
    }
    
    void write_string_field(std::string_view str) noexcept {
        write_string(str);
    }
    
    void write_bytes(std::span<const std::byte> data) noexcept {
        write_u32(static_cast<uint32_t>(data.size()));
        auto offset = buffer_.size();
        buffer_.resize(offset + data.size());
        std::memcpy(buffer_.data() + offset, data.data(), data.size());
    }
    
    void write_bytes_field(std::span<const std::byte> data) noexcept {
        write_bytes(data);
    }
    
    [[nodiscard]] size_t size() const noexcept { return buffer_.size(); }
    [[nodiscard]] size_t position() const noexcept { return buffer_.size(); }

private:
    std::vector<std::byte>& buffer_;
};
}
namespace psyfer {
class PsyferContext {
public:
    struct Config {
        bool generate_encryption_key = true;      // Generate symmetric encryption key
        bool generate_signing_key = true;         // Generate Ed25519 key pair
        bool generate_key_exchange = true;        // Generate X25519 key pair
        std::chrono::hours key_rotation_period{24 * 30}; // Default 30 days
        std::string identity_name;                // Optional identity label
    };
    [[nodiscard]] static result<std::unique_ptr<PsyferContext>> create() noexcept;
    [[nodiscard]] static result<std::unique_ptr<PsyferContext>> create(
        const Config& config
    ) noexcept;
    [[nodiscard]] static result<std::unique_ptr<PsyferContext>> load(
        std::span<const std::byte> encrypted_data,
        std::span<const std::byte, 32> master_key
    ) noexcept;
    [[nodiscard]] result<std::vector<std::byte>> save(
        std::span<const std::byte, 32> master_key
    ) const noexcept;
    struct EncryptResult {
        std::array<std::byte, 12> nonce;
        std::array<std::byte, 16> tag;
    };
    [[nodiscard]] result<EncryptResult> encrypt_aes(
        std::span<std::byte> plaintext,
        std::span<const std::byte> aad = {}
    ) noexcept;
    [[nodiscard]] std::error_code decrypt_aes(
        std::span<std::byte> ciphertext,
        std::span<const std::byte, 12> nonce,
        std::span<const std::byte, 16> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
    [[nodiscard]] result<std::vector<std::byte>> encrypt_string(
        std::string_view plaintext
    ) noexcept;
    [[nodiscard]] result<std::string> decrypt_string(
        std::span<const std::byte> ciphertext
    ) noexcept;
    [[nodiscard]] result<EncryptResult> encrypt_chacha(
        std::span<std::byte> plaintext,
        std::span<const std::byte> aad = {}
    ) noexcept;
    [[nodiscard]] std::error_code decrypt_chacha(
        std::span<std::byte> ciphertext,
        std::span<const std::byte, 12> nonce,
        std::span<const std::byte, 16> tag,
        std::span<const std::byte> aad = {}
    ) noexcept;
    [[nodiscard]] result<std::vector<std::byte>> encrypt_for(
        std::span<const std::byte> plaintext,
        std::span<const std::byte, 32> recipient_public_key
    ) noexcept;
    [[nodiscard]] result<std::vector<std::byte>> decrypt_from(
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, 32> sender_public_key
    ) noexcept;
    [[nodiscard]] std::span<const std::byte, 32> get_public_key() const noexcept {
        return x25519_keypair_.public_key;
    }
    [[nodiscard]] result<std::array<std::byte, 64>> sign(
        std::span<const std::byte> message
    ) noexcept;
    [[nodiscard]] result<std::array<std::byte, 64>> sign_string(
        std::string_view message
    ) noexcept;
    [[nodiscard]] bool verify(
        std::span<const std::byte> message,
        std::span<const std::byte, 64> signature,
        std::span<const std::byte, 32> public_key
    ) noexcept;
    [[nodiscard]] std::span<const std::byte, 32> get_signing_public_key() const noexcept {
        return ed25519_keypair_.public_key;
    }
    [[nodiscard]] std::array<std::byte, 32> hmac256(
        std::span<const std::byte> message
    ) noexcept;
    [[nodiscard]] std::array<std::byte, 64> hmac512(
        std::span<const std::byte> message
    ) noexcept;
    [[nodiscard]] bool verify_hmac256(
        std::span<const std::byte> message,
        std::span<const std::byte, 32> mac
    ) noexcept;
    [[nodiscard]] result<utils::secure_key_256> derive_key(
        std::string_view purpose,
        std::span<const std::byte> salt = {}
    ) noexcept;
    template<size_t KeySize>
    [[nodiscard]] result<utils::secure_key<KeySize>> derive_key_sized(
        std::string_view purpose,
        std::span<const std::byte> salt = {}
    ) noexcept;
    [[nodiscard]] bool needs_rotation() const noexcept;
    [[nodiscard]] std::error_code rotate_keys() noexcept;
    [[nodiscard]] std::chrono::system_clock::time_point created_at() const noexcept {
        return created_at_;
    }
    [[nodiscard]] const std::string& identity() const noexcept {
        return identity_name_;
    }
    [[nodiscard]] std::span<const std::byte, 32> get_psy_key() const noexcept {
        return psy_key_.span();
    }
    template<typename T>
    requires serialization::HasEncryptedSize<T>
    [[nodiscard]] result<std::vector<std::byte>> encrypt_object(const T& obj) noexcept {
        size_t size = obj.encrypted_size();
        std::vector<std::byte> buffer(size);
        
        size_t written = obj.encrypt(buffer, get_psy_key());
        if (written == 0) {
            return std::unexpected(make_error_code(error_code::encryption_failed));
        }
        
        buffer.resize(written);
        return buffer;
    }
    template<typename T>
    requires serialization::HasDecrypt<T>
    [[nodiscard]] result<T> decrypt_object(std::span<const std::byte> data) noexcept {
        T obj;
        size_t consumed = obj.decrypt(data, get_psy_key());
        if (consumed == 0) {
            return std::unexpected(make_error_code(error_code::decryption_failed));
        }
        return obj;
    }
    ~PsyferContext() noexcept;
    PsyferContext(const PsyferContext&) = delete;
    PsyferContext& operator=(const PsyferContext&) = delete;
    PsyferContext(PsyferContext&&) noexcept = default;
    PsyferContext& operator=(PsyferContext&&) noexcept = default;
private:
    PsyferContext() noexcept = default;
    utils::secure_key_256 master_key_;        // Master encryption key
    utils::secure_key_256 hmac_key_;          // HMAC key
    utils::secure_key_256 psy_key_;           // Key for psy-c objects
    crypto::x25519::key_pair x25519_keypair_;
    crypto::ed25519::key_pair ed25519_keypair_;
    std::string identity_name_;
    std::chrono::system_clock::time_point created_at_;
    std::chrono::hours rotation_period_;
    [[nodiscard]] std::error_code initialize_keys(const Config& config) noexcept;
    [[nodiscard]] std::error_code derive_subkeys() noexcept;
};
[[nodiscard]] inline result<std::vector<std::byte>> quick_encrypt(
    std::span<const std::byte> plaintext,
    std::span<const std::byte, 32> key
) noexcept {
    crypto::aes256_gcm cipher;
    std::vector<std::byte> ciphertext(plaintext.size() + 12 + 16);
    std::memcpy(ciphertext.data() + 28, plaintext.data(), plaintext.size());
    std::span<std::byte, 12> nonce(ciphertext.data(), 12);
    auto err = utils::secure_random::generate(nonce);
    if (err) return std::unexpected(err);
    std::span<std::byte> data(ciphertext.data() + 28, plaintext.size());
    std::span<std::byte, 16> tag(ciphertext.data() + 12, 16);
    err = cipher.encrypt(data, key, nonce, tag);
    if (err) return std::unexpected(err);
    ciphertext.resize(28 + plaintext.size());
    return ciphertext;
}
[[nodiscard]] inline result<std::vector<std::byte>> quick_decrypt(
    std::span<const std::byte> ciphertext,
    std::span<const std::byte, 32> key
) noexcept {
    if (ciphertext.size() < 28) {
        return std::unexpected(make_error_code(error_code::invalid_buffer_size));
    }
    crypto::aes256_gcm cipher;
    std::array<std::byte, 12> nonce;
    std::array<std::byte, 16> tag;
    std::memcpy(nonce.data(), ciphertext.data(), 12);
    std::memcpy(tag.data(), ciphertext.data() + 12, 16);
    std::vector<std::byte> plaintext(ciphertext.begin() + 28, ciphertext.end());
    auto err = cipher.decrypt(plaintext, key, nonce, tag);
    if (err) return std::unexpected(err);   
    return plaintext;
}
template<typename T>
[[nodiscard]] inline size_t deserialize_and_decrypt(
    std::span<const std::byte> source_buffer,
    T* target,
    std::span<const std::byte> key
) noexcept requires HasDecrypt<T> {
    return T::decrypt(source_buffer, target, key);
}
template<typename T>
concept HasEncryptedSize = requires(const T& t) {
    { t.encrypted_size() } -> std::convertible_to<size_t>;
};
namespace psyfer::serialization {
enum class WireType : uint8_t {
    VARINT = 0,      // Variable-length integer
    FIXED64 = 1,     // 64-bit fixed
    BYTES = 2,       // Length-delimited
    FIXED32 = 5,     // 32-bit fixed
};
struct FieldHeader {
    uint32_t field_number;
    WireType wire_type;
    [[nodiscard]] constexpr uint32_t encode() const noexcept {
        return (field_number << 3) | static_cast<uint8_t>(wire_type);
    }
    [[nodiscard]] static constexpr FieldHeader decode(uint32_t value) noexcept {
        return {
            .field_number = value >> 3,
            .wire_type = static_cast<WireType>(value & 0x07)
        };
    }
};
class BufferWriter {
public:
    explicit BufferWriter(std::span<std::byte> buffer) noexcept
        : buffer_(buffer), position_(0) {}
    [[nodiscard]] size_t position() const noexcept { return position_; }
    [[nodiscard]] size_t remaining() const noexcept { 
        return position_ < buffer_.size() ? buffer_.size() - position_ : 0;
    }
    [[nodiscard]] bool has_space(size_t bytes) const noexcept {
        return position_ + bytes <= buffer_.size();
    }
    bool write_bytes(std::span<const std::byte> data) noexcept {
        if (!has_space(data.size())) return false;
        std::memcpy(buffer_.data() + position_, data.data(), data.size());
        position_ += data.size();
        return true;
    }
    bool write_varint(uint64_t value) noexcept {
        while (value >= 0x80) {
            if (!write_u8(static_cast<uint8_t>(value | 0x80))) return false;
            value >>= 7;
        }
        return write_u8(static_cast<uint8_t>(value));
    }
    bool write_signed_varint(int64_t value) noexcept {
        // Zigzag encoding: (n << 1) ^ (n >> 63)
        uint64_t encoded = static_cast<uint64_t>((value << 1) ^ (value >> 63));
        return write_varint(encoded);
    }
    bool write_field_header(uint32_t field_number, WireType wire_type) noexcept {
        FieldHeader header{field_number, wire_type};
        return write_varint(header.encode());
    }
    bool write_u8(uint8_t value) noexcept {
        if (!has_space(1)) return false;
        buffer_[position_++] = static_cast<std::byte>(value);
        return true;
    }
    bool write_u32(uint32_t value) noexcept {
        if (!has_space(4)) return false;
        std::memcpy(buffer_.data() + position_, &value, 4);
        position_ += 4;
        return true;
    }
    bool write_u64(uint64_t value) noexcept {
        if (!has_space(8)) return false;
        std::memcpy(buffer_.data() + position_, &value, 8);
        position_ += 8;
        return true;
    }
    bool write_f32(float value) noexcept {
        return write_u32(std::bit_cast<uint32_t>(value));
    }
    bool write_f64(double value) noexcept {
        return write_u64(std::bit_cast<uint64_t>(value));
    }
    bool write_bytes_field(std::span<const std::byte> data) noexcept {
        if (!write_varint(data.size())) return false;
        return write_bytes(data);
    }
    bool write_string_field(std::string_view str) noexcept {
        auto bytes = std::as_bytes(std::span(str));
        return write_bytes_field(bytes);
    }
private:
    std::span<std::byte> buffer_;
    size_t position_;
};
class BufferReader {
public:
    explicit BufferReader(std::span<const std::byte> buffer) noexcept
        : buffer_(buffer), position_(0) {}
    [[nodiscard]] size_t position() const noexcept { return position_; }
    [[nodiscard]] size_t remaining() const noexcept { 
        return position_ < buffer_.size() ? buffer_.size() - position_ : 0;
    }
    [[nodiscard]] bool has_bytes(size_t bytes) const noexcept {
        return position_ + bytes <= buffer_.size();
    }
    bool read_bytes(std::span<std::byte> out) noexcept {
        if (!has_bytes(out.size())) return false;
        std::memcpy(out.data(), buffer_.data() + position_, out.size());
        position_ += out.size();
        return true;
    }
    [[nodiscard]] std::span<const std::byte> peek_bytes(size_t count) const noexcept {
        if (!has_bytes(count)) return {};
        return buffer_.subspan(position_, count);
    }
    bool skip(size_t bytes) noexcept {
        if (!has_bytes(bytes)) return false;
        position_ += bytes;
        return true;
    }
    std::optional<uint64_t> read_varint() noexcept {
        uint64_t result = 0;
        int shift = 0;
        while (true) {
            if (!has_bytes(1)) return std::nullopt;
            uint8_t byte = static_cast<uint8_t>(buffer_[position_++]);
            if (shift >= 64) return std::nullopt; // Overflow
            result |= static_cast<uint64_t>(byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    }
    std::optional<int64_t> read_signed_varint() noexcept {
        auto encoded = read_varint();
        if (!encoded) return std::nullopt;
        uint64_t n = *encoded;
        return static_cast<int64_t>((n >> 1) ^ -static_cast<int64_t>(n & 1));
    }
    std::optional<FieldHeader> read_field_header() noexcept {
        auto encoded = read_varint();
        if (!encoded) return std::nullopt;
        return FieldHeader::decode(static_cast<uint32_t>(*encoded));
    }
    std::optional<uint8_t> read_u8() noexcept {
        if (!has_bytes(1)) return std::nullopt;
        return static_cast<uint8_t>(buffer_[position_++]);
    }
    std::optional<uint32_t> read_u32() noexcept {
        if (!has_bytes(4)) return std::nullopt;
        uint32_t value;
        std::memcpy(&value, buffer_.data() + position_, 4);
        position_ += 4;
        return value;
    }
    std::optional<uint64_t> read_u64() noexcept {
        if (!has_bytes(8)) return std::nullopt;
        uint64_t value;
        std::memcpy(&value, buffer_.data() + position_, 8);
        position_ += 8;
        return value;
    }
    std::optional<float> read_f32() noexcept {
        auto bits = read_u32();
        if (!bits) return std::nullopt;
        return std::bit_cast<float>(*bits);
    }
    std::optional<double> read_f64() noexcept {
        auto bits = read_u64();
        if (!bits) return std::nullopt;
        return std::bit_cast<double>(*bits);
    }
    std::optional<std::span<const std::byte>> read_bytes_field() noexcept {
        auto length = read_varint();
        if (!length || !has_bytes(*length)) return std::nullopt;
        auto data = buffer_.subspan(position_, *length);
        position_ += *length;
        return data;
    }
    std::optional<std::string_view> read_string_field() noexcept {
        auto bytes = read_bytes_field();
        if (!bytes) return std::nullopt;
        return std::string_view(
            reinterpret_cast<const char*>(bytes->data()),
            bytes->size()
        );
    }
private:
    std::span<const std::byte> buffer_;
    size_t position_;
};
[[nodiscard]] inline size_t varint_size(uint64_t value) noexcept {
    size_t size = 1;
    while (value >= 0x80) {
        value >>= 7;
        ++size;
    }
    return size;
}
[[nodiscard]] inline size_t signed_varint_size(int64_t value) noexcept {
    uint64_t encoded = static_cast<uint64_t>((value << 1) ^ (value >> 63));
    return varint_size(encoded);
}
[[nodiscard]] inline size_t field_header_size(uint32_t field_number) noexcept {
    return varint_size(field_number << 3);
}
[[nodiscard]] inline size_t bytes_field_size(size_t data_size) noexcept {
    return varint_size(data_size) + data_size;
}
[[nodiscard]] inline size_t string_field_size(std::string_view str) noexcept {
    return bytes_field_size(str.size());
} }
namespace psyfer::compression {
enum class fpc_compression_level : uint8_t {
    DEFAULT = 10,
    MIN = 1,
    MAX = 32
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

class lz4 final : public compression_algorithm {
public:
    static constexpr size_t MIN_MATCH = 4;          // Minimum match length
    static constexpr size_t MAX_DISTANCE = 65535;   // Maximum offset (16-bit)
    static constexpr size_t HASH_TABLE_SIZE = 4096; // Hash table size (12-bit)
    static constexpr size_t ML_BITS = 4;            // Match length bits in token
    static constexpr size_t ML_MASK = (1U << ML_BITS) - 1;
    static constexpr size_t RUN_BITS = 8 - ML_BITS; // Literal length bits
    static constexpr size_t RUN_MASK = (1U << RUN_BITS) - 1;
    static constexpr uint8_t LAST_LITERAL_SIZE = 5;  // Minimum end literals
    static constexpr uint8_t MFLIMIT = 12;           // Minimum input for match
    lz4() noexcept = default;
    ~lz4() override = default;
    [[nodiscard]] size_t max_compressed_size(size_t uncompressed_size) const noexcept override;
    [[nodiscard]] result<size_t> compress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept override;
    [[nodiscard]] result<size_t> decompress(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept override;
    [[nodiscard]] result<size_t> compress_hc(
        std::span<const std::byte> input,
        std::span<std::byte> output
    ) noexcept;
    [[nodiscard]] result<size_t> compress_fast(
        std::span<const std::byte> input,
        std::span<std::byte> output,
        int acceleration = 1
    ) noexcept;
private:
    [[nodiscard]] static uint32_t hash4(const uint8_t* ptr, uint32_t h) noexcept {
        // Simple but effective hash function
        return ((read32(ptr) * 2654435761U) >> (32 - h));
    }
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
    [[nodiscard]] static result<std::vector<std::byte>> compress_frame(
        std::span<const std::byte> input,
        const frame_descriptor& desc = {}
    ) noexcept;
    [[nodiscard]] static result<std::vector<std::byte>> decompress_frame(
        std::span<const std::byte> input
    ) noexcept;
}; }

} // namespace psyfer
