/**
 * @file logger.cpp
 * @brief A thread-safe logging utility
 */
#include <iomanip>
#include <sys/ioctl.h>
#include <unistd.h>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <iostream>
#include <format>
#include <vector>
#include <cstdlib>
#include <psyfer.hpp>

namespace std {

// Global context singleton implementation
GlobalContext &getGlobalContext() {
    static GlobalContext instance;
    return instance;
}

// Thread-local storage definition
thread_local std::string GlobalContext::thread_context{};
thread_local std::string &thread_context = getGlobalContext().thread_context;

// Helper functions in anonymous namespace (internal linkage)
namespace {

uint64_t getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[maybe_unused]] uint64_t get_now() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;
    std::ostringstream oss;
    char time_buffer[20];
    std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S",
                  std::localtime(&time_t));
    oss << time_buffer << '.' << std::setfill('0') << std::setw(3)
        << ms.count();
    return oss.str();
}

std::string FormatDuration(uint64_t duration_ms) {
    if (duration_ms < 1000)
        return std::to_string(duration_ms) + "ms";
    else if (duration_ms < 60000)
        return std::to_string(duration_ms / 1000.0) + "s";
    else if (duration_ms < 3600000) {
        uint64_t minutes = duration_ms / 60000;
        uint64_t seconds = (duration_ms % 60000) / 1000;
        return std::to_string(minutes) + "m " + std::to_string(seconds) + "s";
    } else {
        uint64_t hours = duration_ms / 3600000;
        uint64_t minutes = (duration_ms % 3600000) / 60000;
        return std::to_string(hours) + "h " + std::to_string(minutes) + "m";
    }
}

[[maybe_unused]] uint64_t getHighPrecisionTimestamp() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::high_resolution_clock::now().time_since_epoch())
        .count();
}

[[maybe_unused]] uint64_t getMicrosecondTimestamp() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void UpdateProgressBar(const ProgressBar &bar) {
    float progress = bar.progress;
    int filled_width = static_cast<int>(bar.width * progress);
    {
        stdout_lock();
        int lines_down =
            getGlobalContext().stdout_current_line.load() - bar.start_line;
        std::ostringstream oss;
        for (int i = 0; i < lines_down; i++) {
            oss << "\033[1A";
        }
        oss << "\033[2K" << "\r";
        if (progress >= 1.0f) {
            uint64_t duration = getCurrentTimestamp() - bar.start_time;
            oss << bar.start_time_str << " [INFO ] [" << bar.thread_name << "] "
                << bar.header << " Completed in " << FormatDuration(duration);
            getGlobalContext().progress_bars.erase(bar.id);
        } else {
            uint64_t elapsed_time = getCurrentTimestamp() - bar.start_time;
            uint64_t estimated_time_remaining =
                (elapsed_time / progress) - elapsed_time;
            std::string time_remaining =
                FormatDuration(estimated_time_remaining);
            oss << bar.start_time_str << " [INFO ] [" << bar.thread_name << "] "
                << bar.header << " [" << std::string(filled_width, '=')
                << std::string(bar.width - filled_width, ' ') << "] "
                << std::fixed << std::setprecision(1) << (progress * 100)
                << "% est:" << time_remaining;
        }
        oss << "\r";
        for (int i = 0; i < lines_down; i++) {
            oss << "\033[1B";
        }
        std::cout << oss.str() << "\r";
        std::cout.flush();
        stdout_unlock();
    }
}

void RedrawAllProgressBars() {
    std::unique_lock lock(getGlobalContext().progress_mutex);
    for (const auto &[id, bar] : getGlobalContext().progress_bars) {
        UpdateProgressBar(bar);
    }
}

} // anonymous namespace

// Public API implementations

std::string get_thread_context() {
    if (!thread_context.empty()) {
        return thread_context;
    }
    // If no context set, use thread ID
    std::ostringstream oss;
    oss << "Thread-" << std::this_thread::get_id();
    return oss.str();
}

void set_internal_log_level(LogLevel level) {
    getGlobalContext().global_log_level = level;
}

void log_message(LogLevel level, const std::string& message) {
    if (getGlobalContext().global_log_level > level)
        return;
    
    std::stringstream oss;
    
    // Add color based on log level
    switch (level) {
        case LogLevel::ERROR:
            oss << "\033[31m";  // Red (not bright)
            break;
        case LogLevel::WARN:
            oss << "\033[33m";  // Yellow (not bright)
            break;
        case LogLevel::DEBUG:
            oss << "\033[34m";  // Blue (not bright)
            break;
        case LogLevel::TRACE:
            oss << "\033[37m";  // Light grey
            break;
        case LogLevel::INFO:
        default:
            break;
    }
    
    // Add timestamp and level
    const char* level_str;
    switch (level) {
        case LogLevel::TRACE: level_str = "TRACE"; break;
        case LogLevel::DEBUG: level_str = "DEBUG"; break;
        case LogLevel::INFO:  level_str = "INFO "; break;
        case LogLevel::WARN:  level_str = "WARN "; break;
        case LogLevel::ERROR: level_str = "ERROR"; break;
    }
    
    oss << GetTimestamp() << " [" << level_str << "] [" << get_thread_context() << "] " << message << "\n";
    
    // Calculate lines for terminal width
    int lines = 0;
    int char_count = 0;
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    int term_width = w.ws_col > 0 ? w.ws_col : 80;
    for (char c : oss.str()) {
        char_count++;
        if (char_count % term_width == 0)
            lines++;
        if (c == '\n') {
            lines++;
            char_count = 0;
        }
    }
    
    // Add color reset for colored levels
    if (level == LogLevel::ERROR || level == LogLevel::WARN || level == LogLevel::DEBUG || level == LogLevel::TRACE) {
        oss << "\033[0m";
    }
    
    // Output with appropriate locking
    if (level == LogLevel::ERROR || level == LogLevel::WARN || level == LogLevel::DEBUG || level == LogLevel::TRACE) {
        stdout_lock();
        std::cout << oss.str();
        std::cout.flush();
        getGlobalContext().stdout_current_line += lines;
        stdout_unlock();
    } else {
        std::cout << oss.str();
        std::cout.flush();
        getGlobalContext().stdout_current_line += lines;
    }
    
    RedrawAllProgressBars();
}

std::function<void(float)> log_progress(const std::string &header,
             const std::string &thread_name) {
    std::string random_id = std::to_string(rand() % 1000000);
    std::thread log_progress_bar_thread([header, random_id, thread_name]() {
        if (!thread_name.empty()) {
            thread_context = thread_name;
        }
        struct winsize w;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
        int term_width = w.ws_col > 0 ? w.ws_col : 80;
        // Calculate bar width: timestamp(26) + level(8) + brackets(4) + thread_name + header + percentage(10) + spaces
        int used_width = 26 + 8 + 4 + get_thread_context().length() + header.length() + 10 + 5;
        int bar_width = term_width - used_width;
        if (bar_width < 10) bar_width = 10;  // Ensure minimum bar width
        if (bar_width > 100) bar_width = 100;  // Cap maximum bar width
        std::string timestamp = GetTimestamp();
        std::ostringstream oss;
        oss << timestamp << " [INFO ] [" << get_thread_context() << "] " << header
            << " [" << std::string(bar_width, ' ') << "] 0%\n";
        {
            stdout_lock();
            std::cout << oss.str() << "\r";
            std::cout.flush();
            {
                std::unique_lock lock(getGlobalContext().progress_mutex);
                ProgressBar progress_bar_instance = {
                    random_id,
                    get_thread_context(),
                    header,
                    timestamp,
                    0.0f,
                    bar_width,
                    getGlobalContext().stdout_current_line.load(),
                    getCurrentTimestamp()};
                getGlobalContext().progress_bars[random_id] =
                    progress_bar_instance;
            }
            getGlobalContext().stdout_current_line += 1;
            stdout_unlock();
        }
    });
    log_progress_bar_thread.detach();
    return [random_id](float progress) mutable {
        std::unique_lock lock(getGlobalContext().progress_mutex);
        if (getGlobalContext().progress_bars.find(random_id) ==
            getGlobalContext().progress_bars.end()) {
            return;
        }
        getGlobalContext().progress_bars[random_id].progress = progress;
        UpdateProgressBar(getGlobalContext().progress_bars[random_id]);
    };
}

// Non-template log function implementations
void log_info(const std::string& message) {
    log_message(LogLevel::INFO, message);
}

void log_error(const std::string& message) {
    log_message(LogLevel::ERROR, message);
}

void log_warn(const std::string& message) {
    log_message(LogLevel::WARN, message);
}

void log_debug(const std::string& message) {
    log_message(LogLevel::DEBUG, message);
}

void log_trace(const std::string& message) {
    log_message(LogLevel::TRACE, message);
}

}
