/**
 * @file code_generator.hpp
 * @brief C++ code generator for psy-c schemas
 */

#pragma once

#include "psy-c/ast.hpp"
#include <string>
#include <sstream>
#include <set>

namespace psyc {

/**
 * @brief C++ code generation options
 */
struct GeneratorOptions {
    std::string namespace_prefix;    // Additional namespace prefix
    bool generate_comments = true;   // Generate doxygen comments
    bool use_exceptions = false;     // Use exceptions vs error codes
    std::string header_guard_prefix = "PSYC_GENERATED";
};

/**
 * @brief C++ code generator
 */
class CodeGenerator {
public:
    /**
     * @brief Generate C++ code from schema
     */
    [[nodiscard]] static std::string generate(
        const Schema& schema,
        const GeneratorOptions& options = {}
    );

private:
    CodeGenerator(const Schema& schema, const GeneratorOptions& options);
    
    [[nodiscard]] std::string generate_code();
    
    // Generation methods
    void generate_header();
    void generate_includes();
    void generate_namespace_begin();
    void generate_namespace_end();
    void generate_forward_declarations();
    void generate_enums();
    void generate_structs();
    void generate_unions();
    
    void generate_enum(const Enum& en);
    void generate_struct(const Struct& st);
    void generate_union(const Union& un);
    void generate_field(const Field& field, const std::string& struct_name);
    
    // Type generation
    [[nodiscard]] std::string cpp_type_name(const Type& type) const;
    [[nodiscard]] std::string primitive_type_name(PrimitiveType type) const;
    
    // Encryption generation
    void generate_encryption_methods(const Struct& st);
    void generate_field_encryption(const Field& field, const std::string& struct_name);
    [[nodiscard]] bool needs_encryption(const Struct& st) const;
    [[nodiscard]] std::string encryption_algorithm(const Annotation* ann) const;
    
    // Compression generation
    void generate_compression_methods(const Struct& st);
    [[nodiscard]] bool needs_compression(const Struct& st) const;
    [[nodiscard]] std::string compression_algorithm(const Annotation* ann) const;
    
    // Signing generation
    void generate_signing_methods(const Struct& st);
    [[nodiscard]] bool needs_signing(const Struct& st) const;
    [[nodiscard]] std::string signing_algorithm(const Annotation* ann) const;
    
    // Helper methods
    void emit(const std::string& text);
    void emit_line(const std::string& text = "");
    void indent();
    void dedent();
    void emit_comment(const std::string& text);
    [[nodiscard]] std::string sanitize_identifier(const std::string& id) const;
    
    const Schema& schema_;
    GeneratorOptions options_;
    std::stringstream output_;
    size_t indent_level_ = 0;
    std::set<std::string> forward_declared_;
};

} // namespace psyc