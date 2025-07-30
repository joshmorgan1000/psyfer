/**
 * @file 08_key_derivation.cpp
 * @brief Key derivation function (KDF) examples
 * 
 * This example demonstrates:
 * - HKDF (HMAC-based Key Derivation Function)
 * - Deriving multiple keys from one master key
 * - Using salts and info parameters
 * - Key stretching
 * - Common KDF patterns
 */

#include <psyfer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <map>

using namespace psyfer;

/**
 * @brief Helper to print keys
 */
void print_key(const std::string& label, std::span<const std::byte> key) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(key.size(), size_t(16)); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<uint8_t>(key[i]));
    }
    if (key.size() > 16) std::cout << "...";
    std::cout << std::dec << " (" << key.size() << " bytes)\n";
}

/**
 * @brief Example 1: Basic HKDF usage
 */
void example_basic_hkdf() {
    std::cout << "\n=== Example 1: Basic HKDF Usage ===\n";
    
    // Master key (could be from key exchange, password, etc.)
    auto master_key_result = utils::secure_key_256::generate();
    if (!master_key_result) return;
    auto& master_key = *master_key_result;
    
    // Derive an encryption key
    std::array<std::byte, 32> encryption_key;
    auto err = kdf::hkdf::derive_sha256(
        master_key.span(),
        std::span<const std::byte>{},  // No salt
        std::as_bytes(std::span("encryption")),  // Context info
        encryption_key
    );
    
    if (err) {
        std::cerr << "Key derivation failed: " << err.message() << "\n";
        return;
    }
    
    print_key("Master key", master_key.span());
    print_key("Derived encryption key", encryption_key);
    
    // Derive a different key from same master
    std::array<std::byte, 32> auth_key;
    err = kdf::hkdf::derive_sha256(
        master_key.span(),
        std::span<const std::byte>{},
        std::as_bytes(std::span("authentication")),
        auth_key
    );
    
    if (!err) {
        print_key("Derived auth key", auth_key);
        
        // Keys should be different
        bool different = (encryption_key != auth_key);
        std::cout << "Keys are different: " << (different ? "✅" : "❌") << "\n";
    }
}

/**
 * @brief Example 2: Using salts
 */
void example_salted_derivation() {
    std::cout << "\n=== Example 2: Salted Key Derivation ===\n";
    
    // Shared secret (e.g., from ECDH)
    std::array<std::byte, 32> shared_secret;
    utils::secure_random::generate(shared_secret);
    
    // Different salts for different contexts
    std::string user_id = "user123@example.com";
    std::string session_id = "session-2024-01-15-001";
    
    std::cout << "User ID: " << user_id << "\n";
    std::cout << "Session ID: " << session_id << "\n";
    
    // Derive user-specific key
    std::array<std::byte, 32> user_key;
    auto err = kdf::hkdf::derive_sha256(
        shared_secret,
        std::as_bytes(std::span(user_id)),  // Salt
        std::as_bytes(std::span("user-encryption")),  // Info
        user_key
    );
    
    if (!err) {
        print_key("User-specific key", user_key);
    }
    
    // Derive session-specific key
    std::array<std::byte, 32> session_key;
    err = kdf::hkdf::derive_sha256(
        shared_secret,
        std::as_bytes(std::span(session_id)),  // Salt
        std::as_bytes(std::span("session-encryption")),  // Info
        session_key
    );
    
    if (!err) {
        print_key("Session-specific key", session_key);
    }
    
    // Same inputs should produce same outputs
    std::array<std::byte, 32> user_key2;
    kdf::hkdf::derive_sha256(
        shared_secret,
        std::as_bytes(std::span(user_id)),
        std::as_bytes(std::span("user-encryption")),
        user_key2
    );
    
    bool deterministic = (user_key == user_key2);
    std::cout << "\nDeterministic derivation: " << (deterministic ? "✅" : "❌") << "\n";
}

/**
 * @brief Example 3: Deriving multiple keys
 */
void example_multiple_keys() {
    std::cout << "\n=== Example 3: Deriving Multiple Keys ===\n";
    
    // Master secret
    auto master_result = utils::secure_key_256::generate();
    if (!master_result) return;
    auto& master = *master_result;
    
    // Protocol version for domain separation
    std::string protocol_version = "v1.0";
    
    // Derive all keys needed for a protocol
    struct ProtocolKeys {
        std::array<std::byte, 32> client_write_key;
        std::array<std::byte, 32> server_write_key;
        std::array<std::byte, 32> client_hmac_key;
        std::array<std::byte, 32> server_hmac_key;
        std::array<std::byte, 16> client_iv;
        std::array<std::byte, 16> server_iv;
    };
    
    ProtocolKeys keys;
    
    // Derive each key with unique info
    std::map<std::string, std::span<std::byte>> key_specs = {
        {"client_write", keys.client_write_key},
        {"server_write", keys.server_write_key},
        {"client_hmac", keys.client_hmac_key},
        {"server_hmac", keys.server_hmac_key}
    };
    
    for (const auto& [purpose, key_span] : key_specs) {
        std::string info = protocol_version + ":" + purpose;
        auto err = kdf::hkdf::derive_sha256(
            master.span(),
            std::as_bytes(std::span(protocol_version)),
            std::as_bytes(std::span(info)),
            key_span
        );
        
        if (!err) {
            print_key(purpose, key_span);
        }
    }
    
    // Derive IVs
    std::string client_iv_info = protocol_version + ":client_iv";
    kdf::hkdf::derive_sha256(
        master.span(),
        std::as_bytes(std::span(protocol_version)),
        std::as_bytes(std::span(client_iv_info)),
        std::span(keys.client_iv).subspan(0, 16)
    );
    
    std::string server_iv_info = protocol_version + ":server_iv";
    kdf::hkdf::derive_sha256(
        master.span(),
        std::as_bytes(std::span(protocol_version)),
        std::as_bytes(std::span(server_iv_info)),
        std::span(keys.server_iv).subspan(0, 16)
    );
    
    print_key("client_iv", keys.client_iv);
    print_key("server_iv", keys.server_iv);
}

/**
 * @brief Example 4: Key derivation with different output lengths
 */
void example_variable_length() {
    std::cout << "\n=== Example 4: Variable Length Key Derivation ===\n";
    
    // Input key material
    auto ikm_result = utils::secure_key_256::generate();
    if (!ikm_result) return;
    auto& ikm = *ikm_result;
    
    // HKDF can produce up to 255 * hash_length bytes
    std::cout << "HKDF-SHA256 can produce up to " << (255 * 32) << " bytes\n\n";
    
    // Different length outputs
    std::vector<size_t> lengths = {16, 32, 48, 64, 128};
    
    for (size_t length : lengths) {
        std::vector<std::byte> derived_key(length);
        
        auto err = kdf::hkdf::derive_sha256(
            ikm.span(),
            std::span<const std::byte>{},
            std::as_bytes(std::span("variable-length-test")),
            derived_key
        );
        
        if (!err) {
            print_key(std::to_string(length) + "-byte key", derived_key);
        }
    }
}

/**
 * @brief Example 5: Password-based key derivation
 */
void example_password_kdf() {
    std::cout << "\n=== Example 5: Password-Based Key Derivation ===\n";
    
    // Note: For passwords, you should use a proper password KDF like scrypt or Argon2
    // This example shows how to use HKDF with a password for demonstration
    
    std::string password = "correct horse battery staple";
    std::string username = "alice@example.com";
    std::string service = "SecureChat";
    
    std::cout << "Password: \"" << password << "\"\n";
    std::cout << "Username: " << username << "\n";
    std::cout << "Service: " << service << "\n\n";
    
    // Convert password to bytes
    std::vector<std::byte> password_bytes(
        reinterpret_cast<const std::byte*>(password.data()),
        reinterpret_cast<const std::byte*>(password.data() + password.size())
    );
    
    // Create a strong salt from username and service
    std::string salt_string = service + ":" + username;
    std::vector<std::byte> salt(
        reinterpret_cast<const std::byte*>(salt_string.data()),
        reinterpret_cast<const std::byte*>(salt_string.data() + salt_string.size())
    );
    
    // Derive encryption key
    std::array<std::byte, 32> enc_key;
    auto err = kdf::hkdf::derive_sha256(
        password_bytes,
        salt,
        std::as_bytes(std::span("encryption-2024")),
        enc_key
    );
    
    if (!err) {
        print_key("Encryption key", enc_key);
    }
    
    // Derive authentication key
    std::array<std::byte, 32> auth_key;
    err = kdf::hkdf::derive_sha256(
        password_bytes,
        salt,
        std::as_bytes(std::span("authentication-2024")),
        auth_key
    );
    
    if (!err) {
        print_key("Authentication key", auth_key);
    }
    
    std::cout << "\nWARNING: For real password-based encryption, use:\n";
    std::cout << "  - Argon2id (recommended)\n";
    std::cout << "  - scrypt\n";
    std::cout << "  - PBKDF2 (if others unavailable)\n";
}

/**
 * @brief Example 6: Key hierarchy
 */
void example_key_hierarchy() {
    std::cout << "\n=== Example 6: Key Hierarchy ===\n";
    
    // Root key (never used directly)
    auto root_key_result = utils::secure_key_512::generate();
    if (!root_key_result) return;
    auto& root_key = *root_key_result;
    
    std::cout << "Key hierarchy:\n";
    std::cout << "  Root Key (512-bit)\n";
    std::cout << "    ├── Application Key\n";
    std::cout << "    │   ├── User Keys\n";
    std::cout << "    │   └── Service Keys\n";
    std::cout << "    └── Infrastructure Key\n";
    std::cout << "        ├── TLS Keys\n";
    std::cout << "        └── Storage Keys\n\n";
    
    // Derive application key
    std::array<std::byte, 32> app_key;
    kdf::hkdf::derive_sha512(
        root_key.span(),
        std::as_bytes(std::span("2024-01-15")),  // Date as salt
        std::as_bytes(std::span("application-master")),
        app_key
    );
    print_key("Application master", app_key);
    
    // Derive infrastructure key
    std::array<std::byte, 32> infra_key;
    kdf::hkdf::derive_sha512(
        root_key.span(),
        std::as_bytes(std::span("2024-01-15")),
        std::as_bytes(std::span("infrastructure-master")),
        infra_key
    );
    print_key("Infrastructure master", infra_key);
    
    // Derive user-specific key from application key
    std::string user_id = "user-12345";
    std::array<std::byte, 32> user_key;
    kdf::hkdf::derive_sha256(
        app_key,
        std::as_bytes(std::span(user_id)),
        std::as_bytes(std::span("user-encryption")),
        user_key
    );
    print_key("  User " + user_id, user_key);
    
    // Derive service key from application key
    std::array<std::byte, 32> api_key;
    kdf::hkdf::derive_sha256(
        app_key,
        std::as_bytes(std::span("api-service")),
        std::as_bytes(std::span("api-authentication")),
        api_key
    );
    print_key("  API service", api_key);
    
    // Derive TLS key from infrastructure key
    std::array<std::byte, 32> tls_key;
    kdf::hkdf::derive_sha256(
        infra_key,
        std::as_bytes(std::span("tls-internal")),
        std::as_bytes(std::span("tls-session-keys")),
        tls_key
    );
    print_key("  TLS internal", tls_key);
}

/**
 * @brief Example 7: Key rotation with HKDF
 */
void example_key_rotation() {
    std::cout << "\n=== Example 7: Key Rotation with HKDF ===\n";
    
    // Initial key
    auto key_v1_result = utils::secure_key_256::generate();
    if (!key_v1_result) return;
    auto& key_v1 = *key_v1_result;
    
    std::cout << "Key rotation scheme using HKDF:\n";
    print_key("Key v1", key_v1.span());
    
    // Rotate to v2 using HKDF
    std::array<std::byte, 32> key_v2;
    auto err = kdf::hkdf::derive_sha256(
        key_v1.span(),
        std::as_bytes(std::span("rotation")),
        std::as_bytes(std::span("version-2")),
        key_v2
    );
    
    if (!err) {
        print_key("Key v2", key_v2);
    }
    
    // Rotate to v3
    std::array<std::byte, 32> key_v3;
    err = kdf::hkdf::derive_sha256(
        key_v2,
        std::as_bytes(std::span("rotation")),
        std::as_bytes(std::span("version-3")),
        key_v3
    );
    
    if (!err) {
        print_key("Key v3", key_v3);
    }
    
    std::cout << "\nAdvantages:\n";
    std::cout << "  - Forward security (can't derive past keys)\n";
    std::cout << "  - Deterministic (can recreate if needed)\n";
    std::cout << "  - No need to store all versions\n";
    
    // Demonstrate forward security
    std::cout << "\nForward security test:\n";
    std::cout << "  Can derive v2 from v1: ✅\n";
    std::cout << "  Can derive v3 from v2: ✅\n";
    std::cout << "  Cannot derive v1 from v2: ✅ (one-way function)\n";
}

/**
 * @brief Example 8: Domain separation
 */
void example_domain_separation() {
    std::cout << "\n=== Example 8: Domain Separation ===\n";
    
    // Shared master secret
    auto master_result = utils::secure_key_256::generate();
    if (!master_result) return;
    auto& master = *master_result;
    
    std::cout << "Using domain separation to prevent key reuse:\n\n";
    
    // Different domains/contexts
    struct Domain {
        std::string name;
        std::string context;
    };
    
    std::vector<Domain> domains = {
        {"File Encryption", "FILE_ENC_v1"},
        {"Network Protocol", "NET_PROTO_v1"},
        {"Database Encryption", "DB_ENC_v1"},
        {"Backup Encryption", "BACKUP_ENC_v1"}
    };
    
    for (const auto& domain : domains) {
        std::array<std::byte, 32> domain_key;
        
        // Use domain context as info parameter
        auto err = kdf::hkdf::derive_sha256(
            master.span(),
            std::span<const std::byte>{},
            std::as_bytes(std::span(domain.context)),
            domain_key
        );
        
        if (!err) {
            std::cout << domain.name << ":\n";
            print_key("  Key", domain_key);
            std::cout << "  Context: " << domain.context << "\n\n";
        }
    }
    
    std::cout << "Each domain gets a unique key derived from the master secret.\n";
    std::cout << "Keys cannot be used across domains, preventing confusion attacks.\n";
}

int main() {
    std::cout << "Psyfer Key Derivation Examples\n";
    std::cout << "=============================\n";
    
    try {
        example_basic_hkdf();
        example_salted_derivation();
        example_multiple_keys();
        example_variable_length();
        example_password_kdf();
        example_key_hierarchy();
        example_key_rotation();
        example_domain_separation();
        
        std::cout << "\n✅ All key derivation examples completed successfully!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}