#include <inkpacket/ink_packet.hpp>
#include <psyfer.hpp>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>
#include <cstring>
#include <array>

namespace ink {

namespace fs = std::filesystem;

class InkPacketBuilder::Impl {
public:
    explicit Impl(const Config& cfg) : config(cfg) {}
    
    bool build(std::string& log, std::string& error) {
        try {
            log.clear();
            
            // Create temp directory for build artifacts
            fs::path temp_dir = fs::temp_directory_path() / ("ink_build_" + std::to_string(rand()));
            fs::create_directories(temp_dir);
            
            log += "Created temp directory: " + temp_dir.string() + "\n";
            
            // Step 1: Build critical components as shared library
            fs::path lib_path = temp_dir / "critical.so";
            if (!build_shared_library(temp_dir, lib_path, log, error)) {
                fs::remove_all(temp_dir);
                return false;
            }
            
            // Step 2: Build main executable
            fs::path exe_path = temp_dir / "main.exe";
            if (!build_main_executable(temp_dir, exe_path, log, error)) {
                fs::remove_all(temp_dir);
                return false;
            }
            
            // Step 3: Package into ink packet
            if (!create_ink_packet(exe_path, lib_path, log, error)) {
                fs::remove_all(temp_dir);
                return false;
            }
            
            // Cleanup
            fs::remove_all(temp_dir);
            log += "Build completed successfully\n";
            return true;
            
        } catch (const std::exception& e) {
            error = "Build failed: " + std::string(e.what());
            return false;
        }
    }
    
private:
    bool build_shared_library(const fs::path& temp_dir, const fs::path& output,
                              std::string& log, std::string& error) {
        std::stringstream cmd;
        cmd << config.compiler << " " << config.cxx_flags;
        cmd << " -shared -fPIC";
        
        // Add critical sources
        for (const auto& src : config.critical_sources) {
            cmd << " " << src;
        }
        
        // Add include directories
        cmd << " -I" << fs::path(config.main_source).parent_path().string();
        
        // Output
        cmd << " -o " << output.string();
        
        log += "Building shared library: " + cmd.str() + "\n";
        
        int result = std::system(cmd.str().c_str());
        if (result != 0) {
            error = "Failed to build shared library";
            return false;
        }
        
        if (config.strip_symbols) {
            std::string strip_cmd = "strip -x " + output.string();
            std::system(strip_cmd.c_str());
        }
        
        return true;
    }
    
    bool build_main_executable(const fs::path& temp_dir, const fs::path& output,
                               std::string& log, std::string& error) {
        // Generate loader stub
        fs::path stub_path = temp_dir / "loader_stub.cpp";
        if (!generate_loader_stub(stub_path, error)) {
            return false;
        }
        
        std::stringstream cmd;
        cmd << config.compiler << " " << config.cxx_flags;
        
        // Add main source and stub
        cmd << " " << config.main_source;
        cmd << " " << stub_path.string();
        
        // Add non-critical sources
        for (const auto& src : config.sources) {
            bool is_critical = false;
            for (const auto& crit : config.critical_sources) {
                if (src == crit) {
                    is_critical = true;
                    break;
                }
            }
            if (!is_critical) {
                cmd << " " << src;
            }
        }
        
        // Add libraries
        for (const auto& lib : config.link_libs) {
            cmd << " -l" << lib;
        }
        
        // Output
        cmd << " -o " << output.string();
        
        log += "Building main executable: " + cmd.str() + "\n";
        
        int result = std::system(cmd.str().c_str());
        if (result != 0) {
            error = "Failed to build main executable";
            return false;
        }
        
        if (config.strip_symbols) {
            std::string strip_cmd = "strip " + output.string();
            std::system(strip_cmd.c_str());
        }
        
        return true;
    }
    
    bool generate_loader_stub(const fs::path& output, std::string& error) {
        std::ofstream stub(output);
        if (!stub) {
            error = "Failed to create loader stub";
            return false;
        }
        
        // Generate code that will load the encrypted library at runtime
        stub << R"(
#include <memory>
#include <stdexcept>

namespace __ink_packet {
    struct LibraryLoader {
        void* handle = nullptr;
        
        LibraryLoader() {
            // This will be replaced with actual loader code
            // For now, just a placeholder
        }
        
        ~LibraryLoader() {
            // Cleanup
        }
        
        template<typename T>
        T get_function(const char* name) {
            // Placeholder - will be implemented properly
            return nullptr;
        }
    };
    
    static std::unique_ptr<LibraryLoader> loader;
    
    void init() {
        if (!loader) {
            loader = std::make_unique<LibraryLoader>();
        }
    }
}

// Initialize before main
__attribute__((constructor))
void __ink_packet_init() {
    __ink_packet::init();
}
)";
        
        return true;
    }
    
    bool create_ink_packet(const fs::path& exe_path, const fs::path& lib_path,
                           std::string& log, std::string& error) {
        // Read executable
        std::vector<uint8_t> exe_data = read_file(exe_path);
        if (exe_data.empty()) {
            error = "Failed to read executable";
            return false;
        }
        
        // Read library
        std::vector<uint8_t> lib_data = read_file(lib_path);
        if (lib_data.empty()) {
            error = "Failed to read library";
            return false;
        }
        
        // Create initial packet structure
        std::vector<uint8_t> packet;
        
        // Reserve space for header
        InkPacketHeader header = {};
        header.magic = INK_PACKET_MAGIC;
        header.version = INK_PACKET_VERSION;
        header.flags = 0;
        header.hash_algo = config.hash_algo;
        header.enc_algo = config.enc_algo;
        
        packet.resize(sizeof(header));
        
        // Append executable
        header.exe_offset = packet.size();
        header.exe_size = exe_data.size();
        packet.insert(packet.end(), exe_data.begin(), exe_data.end());
        
        // Calculate hash of packet so far (header + exe)
        std::vector<uint8_t> partial_hash = calculate_hash(packet);
        
        // Encrypt library using hash-derived key
        std::vector<uint8_t> encrypted_lib = encrypt_payload(lib_data, partial_hash);
        
        // Append encrypted library
        header.payload_offset = packet.size();
        header.payload_size = encrypted_lib.size();
        packet.insert(packet.end(), encrypted_lib.begin(), encrypted_lib.end());
        
        // Calculate final hash including encrypted payload
        std::vector<uint8_t> final_hash = calculate_hash(packet);
        
        // Re-encrypt library with final hash
        encrypted_lib = encrypt_payload(lib_data, final_hash);
        
        // Replace encrypted payload
        std::copy(encrypted_lib.begin(), encrypted_lib.end(), 
                  packet.begin() + header.payload_offset);
        
        // Update header
        header.checksum = 0;
        header.checksum = crc32(reinterpret_cast<uint8_t*>(&header), sizeof(header));
        std::memcpy(packet.data(), &header, sizeof(header));
        
        // Write final packet
        std::ofstream out(config.output_path, std::ios::binary);
        if (!out) {
            error = "Failed to write output file";
            return false;
        }
        
        out.write(reinterpret_cast<const char*>(packet.data()), packet.size());
        
        // Make executable
#ifndef _WIN32
        fs::permissions(config.output_path, 
                        fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                        fs::perm_options::add);
#endif
        
        log += "Created ink packet: " + config.output_path + "\n";
        log += "  Executable size: " + std::to_string(exe_data.size()) + " bytes\n";
        log += "  Protected library size: " + std::to_string(lib_data.size()) + " bytes\n";
        log += "  Total size: " + std::to_string(packet.size()) + " bytes\n";
        
        return true;
    }
    
    std::vector<uint8_t> read_file(const fs::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return {};
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0);
        
        std::vector<uint8_t> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        return data;
    }
    
    std::vector<uint8_t> calculate_hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash;
        
        if (config.hash_algo == 0) { // SHA-256
            hash.resize(32);
            psyfer::hash::sha256::hash(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()),
                std::span<std::byte>(reinterpret_cast<std::byte*>(hash.data()), 32)
            );
        }
        
        return hash;
    }
    
    std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& hash) {
        // Derive encryption key from hash using HMAC-SHA256
        uint8_t key[32];
        const char* context = "ink_packet_key";
        psyfer::hash::hmac_sha256::hmac(
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(hash.data()), hash.size()),
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(context), strlen(context)),
            std::span<std::byte>(reinterpret_cast<std::byte*>(key), 32)
        );
        
        if (config.enc_algo == 0) { // AES-256-GCM
            return encrypt_aes_gcm(key, data);
        }
        
        return {};
    }
    
    std::vector<uint8_t> encrypt_aes_gcm(const uint8_t* key, const std::vector<uint8_t>& data) {
        constexpr size_t IV_LEN = 12;
        constexpr size_t TAG_LEN = 16;
        
        // Generate IV
        std::array<uint8_t, IV_LEN> iv;
        RAND_bytes(iv.data(), iv.size());
        
        auto ctx = make_cipher_ctx();
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv.data());
        
        std::vector<uint8_t> result(IV_LEN + data.size() + TAG_LEN);
        std::copy(iv.begin(), iv.end(), result.begin());
        
        int outl;
        EVP_EncryptUpdate(ctx.get(), result.data() + IV_LEN, &outl, data.data(), data.size());
        EVP_EncryptFinal_ex(ctx.get(), nullptr, &outl);
        
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, 
                            result.data() + IV_LEN + data.size());
        
        return result;
    }
    
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
    
    Config config;
};

InkPacketBuilder::InkPacketBuilder(const Config& config) 
    : impl_(std::make_unique<Impl>(config)), config_(config) {}

InkPacketBuilder::~InkPacketBuilder() = default;

bool InkPacketBuilder::build() {
    return impl_->build(log_, error_);
}

}
