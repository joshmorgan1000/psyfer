/**
 * @file lexer.hpp
 * @brief Lexical analyzer for psy-c schema language
 */

#pragma once

#include "psy-c/ast.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <unordered_map>

namespace psyc {

/**
 * @brief Token types
 */
enum class TokenType {
    // Literals
    IDENTIFIER,
    INTEGER,
    FLOAT,
    STRING,
    
    // Keywords
    NAMESPACE,
    STRUCT,
    ENUM,
    UNION,
    IMPORT,
    LIST,
    MAP,
    TRUE,
    FALSE,
    
    // Primitive types
    BOOL,
    INT8, INT16, INT32, INT64,
    UINT8, UINT16, UINT32, UINT64,
    FLOAT32, FLOAT64,
    BYTES,
    TEXT,
    
    // Symbols
    LBRACE,      // {
    RBRACE,      // }
    LPAREN,      // (
    RPAREN,      // )
    LBRACKET,    // [
    RBRACKET,    // ]
    SEMICOLON,   // ;
    COLON,       // :
    COMMA,       // ,
    DOT,         // .
    EQUALS,      // =
    QUESTION,    // ?
    AT,          // @
    LESS,        // <
    GREATER,     // >
    
    // Special
    COMMENT,
    NEWLINE,
    END_OF_FILE,
    ERROR
};

/**
 * @brief Token representation
 */
struct Token {
    TokenType type;
    std::string value;
    SourceLocation location;
    
    [[nodiscard]] bool is_primitive_type() const noexcept {
        return type >= TokenType::BOOL && type <= TokenType::TEXT;
    }
    
    [[nodiscard]] bool is_keyword() const noexcept {
        return type >= TokenType::NAMESPACE && type <= TokenType::FALSE;
    }
};

/**
 * @brief Lexical analyzer
 */
class Lexer {
public:
    /**
     * @brief Construct lexer with input
     */
    explicit Lexer(std::string_view input, const std::string& filename = "<input>");
    
    /**
     * @brief Get next token
     */
    [[nodiscard]] Token next_token();
    
    /**
     * @brief Peek at next token without consuming
     */
    [[nodiscard]] Token peek_token();
    
    /**
     * @brief Check if at end of input
     */
    [[nodiscard]] bool is_eof() const noexcept { return current_ >= input_.size(); }
    
    /**
     * @brief Get all remaining tokens
     */
    [[nodiscard]] std::vector<Token> tokenize();

private:
    void skip_whitespace();
    void skip_comment();
    void skip_cpp_comment();
    
    [[nodiscard]] char peek_char(size_t offset = 0) const noexcept;
    [[nodiscard]] char peek_ahead(size_t offset) const noexcept;
    char advance_char() noexcept;
    
    [[nodiscard]] Token read_identifier();
    [[nodiscard]] Token read_number();
    [[nodiscard]] Token read_string();
    [[nodiscard]] Token make_token(TokenType type, std::string value = "");
    [[nodiscard]] Token make_error(const std::string& message);
    
    [[nodiscard]] SourceLocation current_location() const noexcept {
        return {filename_, line_, column_};
    }
    
    std::string_view input_;
    std::string filename_;
    size_t current_ = 0;
    size_t line_ = 1;
    size_t column_ = 1;
    std::optional<Token> peeked_;
    
    static const std::unordered_map<std::string, TokenType> keywords_;
};

} // namespace psyc