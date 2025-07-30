/**
 * @file test_psy_compiler.cpp
 * @brief Comprehensive tests for psy-c compiler
 */

#include "psy-c/parser.hpp"
#include "psy-c/code_generator.hpp"
#include "psy-c/impl_generator.hpp"
#include <psyfer.hpp>
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <memory>

namespace fs = std::filesystem;
using namespace psyc;

// Test helper class
class TestReporter {
private:
    struct TestCase {
        std::string name;
        bool passed;
        std::string error_message;
    };
    
    std::vector<TestCase> test_cases_;
    
public:
    void report(const std::string& test_name, bool passed, const std::string& error = "") {
        test_cases_.push_back({test_name, passed, error});
        if (passed) {
            std::cout << "[PASS] " << test_name << std::endl;
        } else {
            std::cout << "[FAIL] " << test_name;
            if (!error.empty()) {
                std::cout << ": " << error;
            }
            std::cout << std::endl;
        }
    }
    
    void summary() const {
        size_t passed = 0;
        for (const auto& tc : test_cases_) {
            if (tc.passed) passed++;
        }
        
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "Total: " << test_cases_.size() 
                  << ", Passed: " << passed 
                  << ", Failed: " << (test_cases_.size() - passed) << std::endl;
        
        if (passed == test_cases_.size()) {
            std::cout << "All tests PASSED!" << std::endl;
        } else {
            std::cout << "\nFailed tests:" << std::endl;
            for (const auto& tc : test_cases_) {
                if (!tc.passed) {
                    std::cout << "  - " << tc.name;
                    if (!tc.error_message.empty()) {
                        std::cout << ": " << tc.error_message;
                    }
                    std::cout << std::endl;
                }
            }
        }
    }
    
    bool all_passed() const {
        for (const auto& tc : test_cases_) {
            if (!tc.passed) return false;
        }
        return true;
    }
};

// Test fixtures
class PsyCompilerTest {
public:
    TestReporter reporter_;
    std::string test_dir_ = "test_output/";
    
    void setup() {
        // Create test directory
        fs::create_directories(test_dir_);
    }
    
    void cleanup() {
        // Remove test directory
        if (fs::exists(test_dir_)) {
            fs::remove_all(test_dir_);
        }
    }
    
    bool write_schema_file(const std::string& filename, const std::string& content) {
        std::ofstream out(test_dir_ + filename);
        if (!out) return false;
        out << content;
        return true;
    }
    
    std::string read_file(const std::string& filename) {
        std::ifstream in(test_dir_ + filename);
        if (!in) return "";
        return std::string((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    }
};

// =====================================================
// Parser Tests
// =====================================================
void test_parser_basic(PsyCompilerTest& test) {
    std::cout << "\n=== Parser Basic Tests ===" << std::endl;
    
    // Test 1: Parse simple struct
    {
        const char* schema = R"(
namespace test;

struct Person {
    name: string;
    age: uint32;
}
)";
        
        test.write_schema_file("simple.psy", schema);
        
        try {
            auto result = Parser::parse_file(test.test_dir_ + "simple.psy");
            test.reporter_.report("Parse simple struct", 
                                result != nullptr && 
                                result->structs.size() == 1 &&
                                result->structs[0]->name == "Person");
        } catch (const std::exception& e) {
            test.reporter_.report("Parse simple struct", false, e.what());
        }
    }
    
    // Test 2: Parse with encryption annotation
    {
        const char* schema = R"(
namespace secure;

@encrypt(algorithm=aes256)
struct SecureMessage {
    @encrypt(algorithm=chacha20)
    content: string;
    
    timestamp: uint64;
    
    @hash(algorithm=sha256)
    checksum: bytes;
}
)";
        
        test.write_schema_file("encrypted.psy", schema);
        
        try {
            auto result = Parser::parse_file(test.test_dir_ + "encrypted.psy");
            bool has_struct_annotation = false;
            bool has_field_annotation = false;
            
            if (result && !result->structs.empty()) {
                // Check struct annotation
                for (const auto& ann : result->structs[0]->annotations) {
                    if (ann->name == "encrypt") {
                        has_struct_annotation = true;
                        break;
                    }
                }
                
                // Check field annotation
                for (const auto& field : result->structs[0]->fields) {
                    if (field->name == "content") {
                        for (const auto& ann : field->annotations) {
                            if (ann->name == "encrypt") {
                                has_field_annotation = true;
                                break;
                            }
                        }
                    }
                }
            }
            
            test.reporter_.report("Parse encryption annotations", 
                                has_struct_annotation && has_field_annotation);
        } catch (const std::exception& e) {
            test.reporter_.report("Parse encryption annotations", false, e.what());
        }
    }
    
    // Test 3: Parse nested structures
    {
        const char* schema = R"(
namespace nested;

struct Address {
    street: string;
    city: string;
    zip: uint32;
}

struct Employee {
    id: uint64;
    name: string;
    @encrypt
    salary: float64;
    addresses: list<Address>;
    metadata: map<string, string>;
}
)";
        
        test.write_schema_file("nested.psy", schema);
        
        try {
            auto result = Parser::parse_file(test.test_dir_ + "nested.psy");
            test.reporter_.report("Parse nested structures", 
                                result != nullptr && 
                                result->structs.size() == 2);
        } catch (const std::exception& e) {
            test.reporter_.report("Parse nested structures", false, e.what());
        }
    }
    
    // Test 4: Parse enums
    {
        const char* schema = R"(
namespace enums;

enum Status {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    FAILED = 3
}

struct Task {
    id: uint64;
    status: Status;
    @compress(algorithm=lz4)
    data: bytes;
}
)";
        
        test.write_schema_file("enums.psy", schema);
        
        try {
            auto result = Parser::parse_file(test.test_dir_ + "enums.psy");
            test.reporter_.report("Parse enums", 
                                result != nullptr && 
                                result->enums.size() == 1 &&
                                result->enums[0]->values.size() == 4);
        } catch (const std::exception& e) {
            test.reporter_.report("Parse enums", false, e.what());
        }
    }
    
    // Test 5: Parse invalid syntax
    {
        const char* schema = R"(
namespace invalid;

struct BadStruct {
    field1 string;  // Missing colon
    field2: ;       // Missing type
}
)";
        
        test.write_schema_file("invalid.psy", schema);
        
        try {
            auto result = Parser::parse_file(test.test_dir_ + "invalid.psy");
            test.reporter_.report("Detect syntax errors", false, 
                                "Should have thrown exception");
        } catch (const std::exception& e) {
            test.reporter_.report("Detect syntax errors", true);
        }
    }
}

// =====================================================
// Code Generator Tests
// =====================================================
void test_code_generator(PsyCompilerTest& test) {
    std::cout << "\n=== Code Generator Tests ===" << std::endl;
    
    // Test 1: Generate basic struct
    {
        const char* schema_str = R"(
namespace test;

struct Person {
    name: string;
    age: uint32;
}
)";
        
        test.write_schema_file("codegen_basic.psy", schema_str);
        
        try {
            auto schema = Parser::parse_file(test.test_dir_ + "codegen_basic.psy");
            
            GeneratorOptions options;
            std::string code = CodeGenerator::generate(*schema, options);
            
            bool has_class = code.find("class Person") != std::string::npos ||
                           code.find("struct Person") != std::string::npos;
            bool has_serialize = code.find("serialize(") != std::string::npos;
            bool has_deserialize = code.find("deserialize(") != std::string::npos;
            bool has_name_field = code.find("name") != std::string::npos;
            bool has_age_field = code.find("age") != std::string::npos;
            
            test.reporter_.report("Generate basic struct code", 
                                has_class && has_serialize && 
                                has_deserialize && has_name_field && has_age_field);
        } catch (const std::exception& e) {
            test.reporter_.report("Generate basic struct code", false, e.what());
        }
    }
    
    // Test 2: Generate encrypted struct
    {
        const char* schema_str = R"(
namespace secure;

@encrypt(algorithm=aes256)
struct SecureMessage {
    content: string;
    timestamp: uint64;
}
)";
        
        test.write_schema_file("codegen_encrypt.psy", schema_str);
        
        try {
            auto schema = Parser::parse_file(test.test_dir_ + "codegen_encrypt.psy");
            
            GeneratorOptions options;
            std::string code = CodeGenerator::generate(*schema, options);
            
            bool has_encrypt = code.find("encrypt(") != std::string::npos;
            bool has_decrypt = code.find("decrypt(") != std::string::npos;
            bool has_aes256 = code.find("aes256") != std::string::npos ||
                            code.find("AES256") != std::string::npos ||
                            code.find("AES-256") != std::string::npos;
            
            test.reporter_.report("Generate encrypted struct", 
                                has_encrypt && has_decrypt && has_aes256);
        } catch (const std::exception& e) {
            test.reporter_.report("Generate encrypted struct", false, e.what());
        }
    }
    
    // Test 3: Generate with namespace
    {
        const char* schema_str = R"(
namespace myapp::protocol;

struct Data {
    value: bytes;
}
)";
        
        test.write_schema_file("codegen_namespace.psy", schema_str);
        
        try {
            auto schema = Parser::parse_file(test.test_dir_ + "codegen_namespace.psy");
            
            GeneratorOptions options;
            options.namespace_prefix = "company";
            std::string code = CodeGenerator::generate(*schema, options);
            
            bool has_namespace = code.find("namespace") != std::string::npos &&
                               (code.find("myapp") != std::string::npos ||
                                code.find("protocol") != std::string::npos ||
                                code.find("company") != std::string::npos);
            
            test.reporter_.report("Generate with custom namespace", has_namespace);
        } catch (const std::exception& e) {
            test.reporter_.report("Generate with custom namespace", false, e.what());
        }
    }
}

// =====================================================
// Implementation Generator Tests
// =====================================================
void test_impl_generator(PsyCompilerTest& test) {
    std::cout << "\n=== Implementation Generator Tests ===" << std::endl;
    
    // Test 1: Generate implementation for encrypted struct
    {
        const char* schema_str = R"(
namespace crypto_test;

@encrypt(algorithm=chacha20)
struct SecureData {
    data: bytes;
}
)";
        
        test.write_schema_file("impl_encrypt.psy", schema_str);
        
        try {
            auto schema = Parser::parse_file(test.test_dir_ + "impl_encrypt.psy");
            
            GeneratorOptions options;
            options.output_header_file = "secure_data.hpp";
            std::string impl_code = ImplGenerator::generate(*schema, options);
            
            bool has_includes = impl_code.find("#include <psyfer.hpp>") != std::string::npos ||
                              impl_code.find("#include \"psyfer.hpp\"") != std::string::npos;
            bool has_encrypt_impl = impl_code.find("encrypt(") != std::string::npos;
            bool has_decrypt_impl = impl_code.find("decrypt(") != std::string::npos;
            bool has_chacha20 = impl_code.find("chacha20") != std::string::npos ||
                              impl_code.find("ChaCha20") != std::string::npos;
            
            test.reporter_.report("Generate encrypted implementation", 
                                has_includes && has_encrypt_impl && 
                                has_decrypt_impl && has_chacha20);
        } catch (const std::exception& e) {
            test.reporter_.report("Generate encrypted implementation", false, e.what());
        }
    }
    
    // Test 2: Generate with compression
    {
        const char* schema_str = R"(
namespace compress_test;

struct CompressedData {
    @compress(algorithm=lz4)
    payload: bytes;
}
)";
        
        test.write_schema_file("impl_compress.psy", schema_str);
        
        try {
            auto schema = Parser::parse_file(test.test_dir_ + "impl_compress.psy");
            
            GeneratorOptions options;
            std::string impl_code = ImplGenerator::generate(*schema, options);
            
            bool has_lz4 = impl_code.find("lz4") != std::string::npos ||
                         impl_code.find("LZ4") != std::string::npos;
            bool has_compress = impl_code.find("compress") != std::string::npos;
            
            test.reporter_.report("Generate compressed field implementation", 
                                has_lz4 && has_compress);
        } catch (const std::exception& e) {
            test.reporter_.report("Generate compressed field implementation", false, e.what());
        }
    }
}

// =====================================================
// End-to-End Tests
// =====================================================
void test_end_to_end(PsyCompilerTest& test) {
    std::cout << "\n=== End-to-End Tests ===" << std::endl;
    
    // Test 1: Complete compilation workflow
    {
        const char* schema = R"(
namespace e2e_test;

@encrypt(algorithm=aes256)
struct UserProfile {
    user_id: uint64;
    
    @encrypt(algorithm=chacha20)
    email: string;
    
    @hash(algorithm=sha256)
    password_hash: bytes;
    
    @compress(algorithm=lz4)
    profile_data: bytes;
    
    created_at: uint64;
}

struct LoginRequest {
    username: string;
    password: string;
    remember_me: bool;
}
)";
        
        test.write_schema_file("user_profile.psy", schema);
        
        try {
            // Parse
            auto parsed_schema = Parser::parse_file(test.test_dir_ + "user_profile.psy");
            
            // Generate code
            GeneratorOptions options;
            options.output_header_file = "user_profile.hpp";
            std::string header_code = CodeGenerator::generate(*parsed_schema, options);
            std::string impl_code = ImplGenerator::generate(*parsed_schema, options);
            
            // Write generated files
            test.write_schema_file("user_profile.hpp", header_code);
            test.write_schema_file("user_profile.cpp", impl_code);
            
            // Verify generated files exist and contain expected content
            std::string header = test.read_file("user_profile.hpp");
            std::string impl = test.read_file("user_profile.cpp");
            
            bool header_ok = !header.empty() && 
                           (header.find("UserProfile") != std::string::npos ||
                            header.find("LoginRequest") != std::string::npos);
            
            bool impl_ok = !impl.empty() &&
                         (impl.find("aes256") != std::string::npos ||
                          impl.find("AES256") != std::string::npos ||
                          impl.find("chacha20") != std::string::npos ||
                          impl.find("ChaCha20") != std::string::npos ||
                          impl.find("sha256") != std::string::npos ||
                          impl.find("SHA256") != std::string::npos ||
                          impl.find("lz4") != std::string::npos ||
                          impl.find("LZ4") != std::string::npos);
            
            test.reporter_.report("End-to-end compilation", header_ok && impl_ok);
        } catch (const std::exception& e) {
            test.reporter_.report("End-to-end compilation", false, e.what());
        }
    }
    
    // Test 2: Error handling in full pipeline
    {
        const char* schema = R"(
namespace error_test;

struct GoodStruct {
    field: string;
}
)";
        
        test.write_schema_file("good.psy", schema);
        
        try {
            auto parsed_schema = Parser::parse_file(test.test_dir_ + "good.psy");
            GeneratorOptions options;
            std::string code = CodeGenerator::generate(*parsed_schema, options);
            
            // Should succeed
            test.reporter_.report("Valid schema compilation", !code.empty());
        } catch (const std::exception& e) {
            test.reporter_.report("Valid schema compilation", false, e.what());
        }
    }
}

// =====================================================
// Main Test Runner
// =====================================================
int main() {
    std::cout << "=== Psy-C Compiler Tests ===" << std::endl;
    
    PsyCompilerTest test;
    test.setup();
    
    // Run all test suites
    test_parser_basic(test);
    test_code_generator(test);
    test_impl_generator(test);
    test_end_to_end(test);
    
    // Show summary
    test.reporter_.summary();
    
    // Cleanup
    test.cleanup();
    
    return test.reporter_.all_passed() ? 0 : 1;
}