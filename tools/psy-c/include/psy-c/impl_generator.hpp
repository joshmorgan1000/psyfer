/**
 * @file impl_generator.hpp
 * @brief Implementation generator for psy-c generated code
 */

#pragma once

#include "psy-c/ast.hpp"
#include "psy-c/code_generator.hpp"
#include <string>
#include <sstream>

namespace psyc {

/**
 * @brief Generates implementation code for psy-c schemas
 * 
 * This generates the actual implementation of serialization,
 * encryption, compression, etc. methods.
 */
class ImplGenerator {
public:
    /**
     * @brief Generate implementation code from schema
     */
    [[nodiscard]] static std::string generate(
        const Schema& schema,
        const GeneratorOptions& options = {}
    );

private:
    ImplGenerator(const Schema& schema, const GeneratorOptions& options);
    
    [[nodiscard]] std::string generate_code();
    
    // Generation methods
    void generate_header();
    void generate_includes();
    void generate_namespace_begin();
    void generate_namespace_end();
    
    // Implementation generation
    void generate_struct_impls();
    void generate_struct_impl(const Struct& st);
    void generate_serialization_impl(const Struct& st);
    void generate_deserialization_impl(const Struct& st);
    void generate_encryption_impl(const Struct& st);
    void generate_compression_impl(const Struct& st);
    void generate_signing_impl(const Struct& st);
    
    // Field encryption handling
    void generate_field_encryption(const Struct& st);
    [[nodiscard]] std::string get_encryption_algorithm(const Field& field) const;
    [[nodiscard]] std::string get_encryption_algorithm(const Struct& st) const;
    
    // Compression handling
    [[nodiscard]] std::string get_compression_algorithm(const Field& field) const;
    [[nodiscard]] std::string get_compression_algorithm(const Struct& st) const;
    
    // Helper methods
    void emit(const std::string& text);
    void emit_line(const std::string& text = "");
    void indent();
    void dedent();
    [[nodiscard]] bool has_encrypted_fields(const Struct& st) const;
    [[nodiscard]] bool has_compressed_fields(const Struct& st) const;
    [[nodiscard]] std::string primitive_type_name(PrimitiveType type) const;
    
    const Schema& schema_;
    GeneratorOptions options_;
    std::stringstream output_;
    size_t indent_level_ = 0;
};

} // namespace psyc