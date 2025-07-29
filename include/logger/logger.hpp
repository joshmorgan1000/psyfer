#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <sstream>
#include <iostream>
#include <format>
#include <functional>
#include <concepts>
#include <mutex>
#include <unordered_map>
#include <memory>
#include <chrono>
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
}
