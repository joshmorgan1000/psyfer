/**
 * @file parser.cpp
 * @brief Parser implementation
 */

#include "psy-c/parser.hpp"
#include <fstream>
#include <sstream>

namespace psyc {

std::unique_ptr<Schema> Parser::parse(const std::string& input, const std::string& filename) {
    Lexer lexer(input, filename);
    Parser parser(lexer);
    return parser.parse_schema();
}

std::unique_ptr<Schema> Parser::parse_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse(buffer.str(), filename);
}

Parser::Parser(Lexer& lexer) : lexer_(lexer) {
    // Prime the parser with the first token
    current_ = lexer_.next_token();
}

std::unique_ptr<Schema> Parser::parse_schema() {
    auto schema = std::make_unique<Schema>();
    
    // Optional namespace declaration
    if (check(TokenType::NAMESPACE)) {
        schema->namespace_decl = parse_namespace();
    }
    
    // Parse top-level declarations
    while (!check(TokenType::END_OF_FILE)) {
        if (match(TokenType::IMPORT)) {
            schema->imports.push_back(parse_import());
        } else if (check(TokenType::AT) || match(TokenType::STRUCT)) {
            schema->structs.push_back(parse_struct());
        } else if (match(TokenType::ENUM)) {
            schema->enums.push_back(parse_enum());
        } else if (match(TokenType::UNION)) {
            schema->unions.push_back(parse_union());
        } else {
            error("Expected struct, enum, union, or import declaration");
        }
    }
    
    return schema;
}

std::unique_ptr<Namespace> Parser::parse_namespace() {
    consume(TokenType::NAMESPACE, "Expected 'namespace'");
    
    auto ns = std::make_unique<Namespace>();
    set_location(*ns);
    
    // Parse namespace components
    do {
        Token id = consume(TokenType::IDENTIFIER, "Expected namespace identifier");
        ns->components.push_back(id.value);
    } while (match(TokenType::DOT));
    
    consume(TokenType::SEMICOLON, "Expected ';' after namespace declaration");
    
    return ns;
}

std::unique_ptr<Import> Parser::parse_import() {
    auto import = std::make_unique<Import>();
    set_location(*import);
    
    Token path = consume(TokenType::STRING, "Expected import path");
    import->path = path.value;
    
    // Optional alias
    if (match(TokenType::IDENTIFIER)) {
        if (previous_.value == "as") {
            Token alias = consume(TokenType::IDENTIFIER, "Expected import alias");
            import->alias = alias.value;
        } else {
            error("Expected 'as' for import alias");
        }
    }
    
    consume(TokenType::SEMICOLON, "Expected ';' after import");
    
    return import;
}

std::unique_ptr<Struct> Parser::parse_struct() {
    auto st = std::make_unique<Struct>();
    
    // Parse annotations
    if (check(TokenType::AT)) {
        st->annotations = parse_annotations();
        consume(TokenType::STRUCT, "Expected 'struct' after annotations");
    }
    
    set_location(*st);
    
    Token name = consume(TokenType::IDENTIFIER, "Expected struct name");
    st->name = name.value;
    
    consume(TokenType::LBRACE, "Expected '{' after struct name");
    
    // Parse fields
    while (!check(TokenType::RBRACE) && !check(TokenType::END_OF_FILE)) {
        // Check for field annotations
        std::vector<std::unique_ptr<Annotation>> field_annotations;
        if (check(TokenType::AT)) {
            field_annotations = parse_annotations();
        }
        
        auto field = parse_field();
        // Merge annotations
        for (auto& ann : field_annotations) {
            field->annotations.push_back(std::move(ann));
        }
        st->fields.push_back(std::move(field));
    }
    
    consume(TokenType::RBRACE, "Expected '}' after struct fields");
    
    return st;
}

std::unique_ptr<Field> Parser::parse_field() {
    auto field = std::make_unique<Field>();
    
    // Field name
    Token name = consume(TokenType::IDENTIFIER, "Expected field name");
    field->name = name.value;
    set_location(*field);
    
    consume(TokenType::COLON, "Expected ':' after field name");
    
    // Field type
    field->type = parse_type();
    
    // Optional annotations
    if (check(TokenType::AT)) {
        field->annotations = parse_annotations();
    }
    
    // Optional default value
    if (match(TokenType::EQUALS)) {
        Token value = advance();
        if (value.type == TokenType::INTEGER || 
            value.type == TokenType::FLOAT || 
            value.type == TokenType::STRING ||
            value.type == TokenType::TRUE ||
            value.type == TokenType::FALSE) {
            field->default_value = value.value;
        } else {
            error("Expected literal value for field default");
        }
    }
    
    consume(TokenType::SEMICOLON, "Expected ';' after field");
    
    return field;
}

Type Parser::parse_type() {
    Type type;
    
    // Check for list type
    if (match(TokenType::LIST)) {
        consume(TokenType::LESS, "Expected '<' after 'list'");
        auto element_type = std::make_shared<Type>(parse_type());
        consume(TokenType::GREATER, "Expected '>' after list element type");
        type.kind = element_type;
    }
    // Check for map type
    else if (match(TokenType::MAP)) {
        consume(TokenType::LESS, "Expected '<' after 'map'");
        auto key_type = std::make_shared<Type>(parse_type());
        consume(TokenType::COMMA, "Expected ',' after map key type");
        auto value_type = std::make_shared<Type>(parse_type());
        consume(TokenType::GREATER, "Expected '>' after map value type");
        type.kind = std::make_pair(key_type, value_type);
    }
    // Primitive types
    else if (current().is_primitive_type()) {
        Token prim = advance();
        switch (prim.type) {
            case TokenType::BOOL: type.kind = PrimitiveType::BOOL; break;
            case TokenType::INT8: type.kind = PrimitiveType::INT8; break;
            case TokenType::INT16: type.kind = PrimitiveType::INT16; break;
            case TokenType::INT32: type.kind = PrimitiveType::INT32; break;
            case TokenType::INT64: type.kind = PrimitiveType::INT64; break;
            case TokenType::UINT8: type.kind = PrimitiveType::UINT8; break;
            case TokenType::UINT16: type.kind = PrimitiveType::UINT16; break;
            case TokenType::UINT32: type.kind = PrimitiveType::UINT32; break;
            case TokenType::UINT64: type.kind = PrimitiveType::UINT64; break;
            case TokenType::FLOAT32: type.kind = PrimitiveType::FLOAT32; break;
            case TokenType::FLOAT64: type.kind = PrimitiveType::FLOAT64; break;
            case TokenType::BYTES: type.kind = PrimitiveType::BYTES; break;
            case TokenType::TEXT: type.kind = PrimitiveType::TEXT; break;
            default: error("Unexpected primitive type");
        }
    }
    // Named type
    else if (check(TokenType::IDENTIFIER)) {
        Token name = advance();
        type.kind = name.value;
    }
    else {
        error("Expected type");
    }
    
    // Optional modifier
    if (match(TokenType::QUESTION)) {
        type.optional = true;
    }
    
    return type;
}

std::unique_ptr<Enum> Parser::parse_enum() {
    auto en = std::make_unique<Enum>();
    set_location(*en);
    
    Token name = consume(TokenType::IDENTIFIER, "Expected enum name");
    en->name = name.value;
    
    consume(TokenType::LBRACE, "Expected '{' after enum name");
    
    // Parse enum values
    while (!check(TokenType::RBRACE) && !check(TokenType::END_OF_FILE)) {
        en->values.push_back(parse_enum_value());
    }
    
    consume(TokenType::RBRACE, "Expected '}' after enum values");
    
    return en;
}

std::unique_ptr<EnumValue> Parser::parse_enum_value() {
    auto val = std::make_unique<EnumValue>();
    
    Token name = consume(TokenType::IDENTIFIER, "Expected enum value name");
    val->name = name.value;
    set_location(*val);
    
    consume(TokenType::EQUALS, "Expected '=' after enum value name");
    
    Token num = consume(TokenType::INTEGER, "Expected integer value for enum");
    val->value = std::stoi(num.value);
    
    consume(TokenType::SEMICOLON, "Expected ';' after enum value");
    
    return val;
}

std::unique_ptr<Union> Parser::parse_union() {
    auto un = std::make_unique<Union>();
    set_location(*un);
    
    Token name = consume(TokenType::IDENTIFIER, "Expected union name");
    un->name = name.value;
    
    consume(TokenType::LBRACE, "Expected '{' after union name");
    
    // Parse union members
    while (!check(TokenType::RBRACE) && !check(TokenType::END_OF_FILE)) {
        un->members.push_back(parse_union_member());
    }
    
    consume(TokenType::RBRACE, "Expected '}' after union members");
    
    return un;
}

std::unique_ptr<UnionMember> Parser::parse_union_member() {
    auto member = std::make_unique<UnionMember>();
    
    Token name = consume(TokenType::IDENTIFIER, "Expected union member name");
    member->name = name.value;
    set_location(*member);
    
    consume(TokenType::COLON, "Expected ':' after union member name");
    
    Token type = consume(TokenType::IDENTIFIER, "Expected type name for union member");
    member->type_name = type.value;
    
    consume(TokenType::SEMICOLON, "Expected ';' after union member");
    
    return member;
}

std::vector<std::unique_ptr<Annotation>> Parser::parse_annotations() {
    std::vector<std::unique_ptr<Annotation>> annotations;
    
    while (match(TokenType::AT)) {
        annotations.push_back(parse_annotation());
    }
    
    return annotations;
}

std::unique_ptr<Annotation> Parser::parse_annotation() {
    auto ann = std::make_unique<Annotation>();
    set_location(*ann);
    
    Token name = consume(TokenType::IDENTIFIER, "Expected annotation name");
    ann->name = name.value;
    
    // Optional parameters
    if (match(TokenType::LPAREN)) {
        // Parse key-value pairs
        do {
            Token key = consume(TokenType::IDENTIFIER, "Expected parameter name");
            consume(TokenType::EQUALS, "Expected '=' after parameter name");
            
            // Accept either string or identifier for parameter value
            Token value;
            if (check(TokenType::STRING)) {
                value = advance();
            } else if (check(TokenType::IDENTIFIER) || current().is_primitive_type()) {
                value = advance();
            } else {
                error("Expected string or identifier value for parameter");
            }
            ann->parameters[key.value] = value.value;
        } while (match(TokenType::COMMA));
        
        consume(TokenType::RPAREN, "Expected ')' after annotation parameters");
    }
    
    return ann;
}

Token Parser::advance() {
    if (!check(TokenType::END_OF_FILE)) {
        previous_ = current_;
        current_ = lexer_.next_token();
    }
    return previous_;
}

Token Parser::consume(TokenType expected, const std::string& message) {
    if (check(expected)) {
        return advance();
    }
    error(message);
}

bool Parser::match(TokenType type) {
    if (check(type)) {
        advance();
        return true;
    }
    return false;
}

bool Parser::check(TokenType type) const {
    return current_.type == type;
}

void Parser::error(const std::string& message) {
    throw ParseError(message, current_.location);
}

} // namespace psyc