/**
 * @file parser.hpp
 * @brief Parser for psy-c schema language
 */

#pragma once

#include "psy-c/ast.hpp"
#include "psy-c/lexer.hpp"
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>

namespace psyc {

/**
 * @brief Parse error exception
 */
class ParseError : public std::runtime_error {
public:
    ParseError(const std::string& message, const SourceLocation& location)
        : std::runtime_error(format_message(message, location))
        , location_(location) {}
    
    [[nodiscard]] const SourceLocation& location() const noexcept { return location_; }
    
private:
    static std::string format_message(const std::string& msg, const SourceLocation& loc) {
        return loc.filename + ":" + std::to_string(loc.line) + ":" + 
               std::to_string(loc.column) + ": error: " + msg;
    }
    
    SourceLocation location_;
};

/**
 * @brief Parser for psy-c schemas
 */
class Parser {
public:
    /**
     * @brief Parse a schema from string
     */
    [[nodiscard]] static std::unique_ptr<Schema> parse(
        const std::string& input,
        const std::string& filename = "<input>"
    );
    
    /**
     * @brief Parse a schema from file
     */
    [[nodiscard]] static std::unique_ptr<Schema> parse_file(const std::string& filename);

private:
    explicit Parser(Lexer& lexer);
    
    [[nodiscard]] std::unique_ptr<Schema> parse_schema();
    [[nodiscard]] std::unique_ptr<Namespace> parse_namespace();
    [[nodiscard]] std::unique_ptr<Import> parse_import();
    [[nodiscard]] std::unique_ptr<Struct> parse_struct();
    [[nodiscard]] std::unique_ptr<Enum> parse_enum();
    [[nodiscard]] std::unique_ptr<Union> parse_union();
    [[nodiscard]] std::unique_ptr<Field> parse_field();
    [[nodiscard]] std::unique_ptr<EnumValue> parse_enum_value();
    [[nodiscard]] std::unique_ptr<UnionMember> parse_union_member();
    [[nodiscard]] std::vector<std::unique_ptr<Annotation>> parse_annotations();
    [[nodiscard]] std::unique_ptr<Annotation> parse_annotation();
    [[nodiscard]] Type parse_type();
    
    // Helper methods
    [[nodiscard]] Token current() const { return current_; }
    [[nodiscard]] Token peek() { return lexer_.peek_token(); }
    
    Token advance();
    Token consume(TokenType expected, const std::string& message);
    bool match(TokenType type);
    bool check(TokenType type) const;
    
    [[noreturn]] void error(const std::string& message);
    
    template<typename T>
    void set_location(T& node) {
        node.set_location(current_.location);
    }
    
    Lexer& lexer_;
    Token current_;
    Token previous_;
};

} // namespace psyc