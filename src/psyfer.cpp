#include <psyfer.hpp>

namespace psyfer {

std::string error_category_impl::message(int ev) const {
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
        case error_code::unknown_error:
            return "Unknown error";
        default:
            return "Unknown error code";
    }
}

const std::error_category& get_error_category() noexcept {
    static error_category_impl instance{};
    return instance;
}

} // namespace psyfer
