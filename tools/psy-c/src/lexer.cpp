/**
 * @file lexer.cpp
 * @brief Lexical analyzer implementation
 */

#include "psy-c/lexer.hpp"
#include <cctype>
#include <algorithm>

namespace psyc {

const std::unordered_map<std::string, TokenType> Lexer::keywords_ = {
    {"namespace", TokenType::NAMESPACE},
    {"struct", TokenType::STRUCT},
    {"enum", TokenType::ENUM},
    {"union", TokenType::UNION},
    {"import", TokenType::IMPORT},
    {"list", TokenType::LIST},
    {"map", TokenType::MAP},
    {"true", TokenType::TRUE},
    {"false", TokenType::FALSE},
    {"bool", TokenType::BOOL},
    {"int8", TokenType::INT8},
    {"int16", TokenType::INT16},
    {"int32", TokenType::INT32},
    {"int64", TokenType::INT64},
    {"uint8", TokenType::UINT8},
    {"uint16", TokenType::UINT16},
    {"uint32", TokenType::UINT32},
    {"uint64", TokenType::UINT64},
    {"float32", TokenType::FLOAT32},
    {"float64", TokenType::FLOAT64},
    {"bytes", TokenType::BYTES},
    {"text", TokenType::TEXT}
};

Lexer::Lexer(std::string_view input, const std::string& filename)
    : input_(input), filename_(filename) {}

Token Lexer::next_token() {
    if (peeked_) {
        Token tok = *peeked_;
        peeked_.reset();
        return tok;
    }
    
    skip_whitespace();
    
    if (is_eof()) {
        return make_token(TokenType::END_OF_FILE);
    }
    
    char ch = peek_char();
    
    // Comments
    if (ch == '#') {
        skip_comment();
        return next_token();
    }
    
    // Identifiers and keywords
    if (std::isalpha(ch) || ch == '_') {
        return read_identifier();
    }
    
    // Numbers
    if (std::isdigit(ch)) {
        return read_number();
    }
    
    // Strings
    if (ch == '"') {
        return read_string();
    }
    
    // Single character tokens
    switch (ch) {
        case '{': advance_char(); return make_token(TokenType::LBRACE, "{");
        case '}': advance_char(); return make_token(TokenType::RBRACE, "}");
        case '(': advance_char(); return make_token(TokenType::LPAREN, "(");
        case ')': advance_char(); return make_token(TokenType::RPAREN, ")");
        case '[': advance_char(); return make_token(TokenType::LBRACKET, "[");
        case ']': advance_char(); return make_token(TokenType::RBRACKET, "]");
        case ';': advance_char(); return make_token(TokenType::SEMICOLON, ";");
        case ':': advance_char(); return make_token(TokenType::COLON, ":");
        case ',': advance_char(); return make_token(TokenType::COMMA, ",");
        case '.': advance_char(); return make_token(TokenType::DOT, ".");
        case '=': advance_char(); return make_token(TokenType::EQUALS, "=");
        case '?': advance_char(); return make_token(TokenType::QUESTION, "?");
        case '@': advance_char(); return make_token(TokenType::AT, "@");
        case '<': advance_char(); return make_token(TokenType::LESS, "<");
        case '>': advance_char(); return make_token(TokenType::GREATER, ">");
        default:
            advance_char();
            return make_error(std::string("Unexpected character: ") + ch);
    }
}

Token Lexer::peek_token() {
    if (!peeked_) {
        peeked_ = next_token();
    }
    return *peeked_;
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    while (!is_eof()) {
        Token tok = next_token();
        if (tok.type == TokenType::END_OF_FILE) break;
        tokens.push_back(tok);
    }
    return tokens;
}

void Lexer::skip_whitespace() {
    while (!is_eof()) {
        char ch = peek_char();
        if (ch == ' ' || ch == '\t' || ch == '\r') {
            advance_char();
        } else if (ch == '\n') {
            advance_char();
            line_++;
            column_ = 1;
        } else {
            break;
        }
    }
}

void Lexer::skip_comment() {
    // Skip the #
    advance_char();
    
    // Skip until end of line
    while (!is_eof() && peek_char() != '\n') {
        advance_char();
    }
}

char Lexer::peek_char(size_t offset) const noexcept {
    size_t pos = current_ + offset;
    return pos < input_.size() ? input_[pos] : '\0';
}

char Lexer::advance_char() noexcept {
    if (current_ < input_.size()) {
        char ch = input_[current_++];
        column_++;
        return ch;
    }
    return '\0';
}

Token Lexer::read_identifier() {
    SourceLocation loc = current_location();
    std::string value;
    
    while (!is_eof()) {
        char ch = peek_char();
        if (std::isalnum(ch) || ch == '_') {
            value += advance_char();
        } else {
            break;
        }
    }
    
    // Check if it's a keyword
    auto it = keywords_.find(value);
    TokenType type = (it != keywords_.end()) ? it->second : TokenType::IDENTIFIER;
    
    Token tok = make_token(type, value);
    tok.location = loc;
    return tok;
}

Token Lexer::read_number() {
    SourceLocation loc = current_location();
    std::string value;
    bool has_dot = false;
    
    while (!is_eof()) {
        char ch = peek_char();
        if (std::isdigit(ch)) {
            value += advance_char();
        } else if (ch == '.' && !has_dot && std::isdigit(peek_char(1))) {
            has_dot = true;
            value += advance_char();
        } else {
            break;
        }
    }
    
    TokenType type = has_dot ? TokenType::FLOAT : TokenType::INTEGER;
    Token tok = make_token(type, value);
    tok.location = loc;
    return tok;
}

Token Lexer::read_string() {
    SourceLocation loc = current_location();
    std::string value;
    
    // Skip opening quote
    advance_char();
    
    while (!is_eof()) {
        char ch = peek_char();
        if (ch == '"') {
            advance_char();
            break;
        } else if (ch == '\\') {
            advance_char();
            if (!is_eof()) {
                char escape = advance_char();
                switch (escape) {
                    case 'n': value += '\n'; break;
                    case 't': value += '\t'; break;
                    case 'r': value += '\r'; break;
                    case '\\': value += '\\'; break;
                    case '"': value += '"'; break;
                    default: value += escape; break;
                }
            }
        } else if (ch == '\n') {
            return make_error("Unterminated string literal");
        } else {
            value += advance_char();
        }
    }
    
    Token tok = make_token(TokenType::STRING, value);
    tok.location = loc;
    return tok;
}

Token Lexer::make_token(TokenType type, std::string value) {
    return Token{type, std::move(value), current_location()};
}

Token Lexer::make_error(const std::string& message) {
    return Token{TokenType::ERROR, message, current_location()};
}

} // namespace psyc