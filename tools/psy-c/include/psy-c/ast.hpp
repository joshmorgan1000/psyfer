/**
 * @file ast.hpp
 * @brief Abstract Syntax Tree definitions for psy-c schema language
 */

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <map>

namespace psyc {

// Forward declarations
struct Type;
struct Field;
struct Annotation;

/**
 * @brief Source location information
 */
struct SourceLocation {
    std::string filename;
    size_t line = 0;
    size_t column = 0;
};

/**
 * @brief Base class for all AST nodes
 */
class ASTNode {
public:
    virtual ~ASTNode() = default;
    
    /**
     * @brief Get the source location of this node
     */
    [[nodiscard]] const SourceLocation& location() const noexcept { return location_; }
    
    /**
     * @brief Set the source location
     */
    void set_location(const SourceLocation& loc) noexcept { location_ = loc; }
    
protected:
    SourceLocation location_;
};

/**
 * @brief Primitive type kinds
 */
enum class PrimitiveType {
    BOOL,
    INT8, INT16, INT32, INT64,
    UINT8, UINT16, UINT32, UINT64,
    FLOAT32, FLOAT64,
    BYTES,
    TEXT
};

/**
 * @brief Type representation
 */
struct Type;

struct Type {
    std::variant<
        PrimitiveType,                    // Primitive type
        std::string,                      // Named type reference
        std::shared_ptr<Type>,            // List<T>
        std::pair<std::shared_ptr<Type>,  // Map<K, V>
                  std::shared_ptr<Type>>
    > kind;
    
    bool optional = false;  // T?
    
    [[nodiscard]] bool is_primitive() const noexcept {
        return std::holds_alternative<PrimitiveType>(kind);
    }
    
    [[nodiscard]] bool is_named() const noexcept {
        return std::holds_alternative<std::string>(kind);
    }
    
    [[nodiscard]] bool is_list() const noexcept {
        return std::holds_alternative<std::shared_ptr<Type>>(kind);
    }
    
    [[nodiscard]] bool is_map() const noexcept {
        return std::holds_alternative<std::pair<std::shared_ptr<Type>, 
                                               std::shared_ptr<Type>>>(kind);
    }
};

/**
 * @brief Annotation (e.g., @encrypt, @authenticate)
 */
struct Annotation : public ASTNode {
    std::string name;
    std::map<std::string, std::string> parameters;
    
    /**
     * @brief Get parameter value
     */
    [[nodiscard]] std::optional<std::string> get_parameter(const std::string& key) const {
        auto it = parameters.find(key);
        return it != parameters.end() ? std::optional(it->second) : std::nullopt;
    }
};

/**
 * @brief Field definition
 */
struct Field : public ASTNode {
    std::string name;
    Type type;
    std::vector<std::unique_ptr<Annotation>> annotations;
    std::optional<std::string> default_value;
    
    /**
     * @brief Check if field has a specific annotation
     */
    [[nodiscard]] bool has_annotation(const std::string& name) const noexcept {
        for (const auto& ann : annotations) {
            if (ann->name == name) return true;
        }
        return false;
    }
    
    /**
     * @brief Get annotation by name
     */
    [[nodiscard]] const Annotation* get_annotation(const std::string& name) const noexcept {
        for (const auto& ann : annotations) {
            if (ann->name == name) return ann.get();
        }
        return nullptr;
    }
};

/**
 * @brief Struct definition
 */
struct Struct : public ASTNode {
    std::string name;
    std::vector<std::unique_ptr<Field>> fields;
    std::vector<std::unique_ptr<Annotation>> annotations;
    
    /**
     * @brief Check if struct has encryption annotation
     */
    [[nodiscard]] bool is_encrypted() const noexcept {
        for (const auto& ann : annotations) {
            if (ann->name == "encrypt") return true;
        }
        return false;
    }
    
    /**
     * @brief Check if struct has a specific annotation
     */
    [[nodiscard]] bool has_annotation(const std::string& name) const noexcept {
        for (const auto& ann : annotations) {
            if (ann->name == name) return true;
        }
        return false;
    }
    
    /**
     * @brief Get annotation by name
     */
    [[nodiscard]] const Annotation* get_annotation(const std::string& name) const noexcept {
        for (const auto& ann : annotations) {
            if (ann->name == name) return ann.get();
        }
        return nullptr;
    }
};

/**
 * @brief Enum value
 */
struct EnumValue : public ASTNode {
    std::string name;
    int32_t value;
};

/**
 * @brief Enum definition
 */
struct Enum : public ASTNode {
    std::string name;
    std::vector<std::unique_ptr<EnumValue>> values;
};

/**
 * @brief Union member
 */
struct UnionMember : public ASTNode {
    std::string name;
    std::string type_name;
};

/**
 * @brief Union definition (tagged union)
 */
struct Union : public ASTNode {
    std::string name;
    std::vector<std::unique_ptr<UnionMember>> members;
};

/**
 * @brief Namespace declaration
 */
struct Namespace : public ASTNode {
    std::vector<std::string> components;  // e.g., ["example", "crypto"]
    
    /**
     * @brief Get full namespace as string
     */
    [[nodiscard]] std::string to_string() const {
        std::string result;
        for (size_t i = 0; i < components.size(); ++i) {
            if (i > 0) result += ".";
            result += components[i];
        }
        return result;
    }
};

/**
 * @brief Import statement
 */
struct Import : public ASTNode {
    std::string path;
    std::optional<std::string> alias;
};

/**
 * @brief Schema file (compilation unit)
 */
struct Schema : public ASTNode {
    std::optional<std::unique_ptr<Namespace>> namespace_decl;
    std::vector<std::unique_ptr<Import>> imports;
    std::vector<std::unique_ptr<Struct>> structs;
    std::vector<std::unique_ptr<Enum>> enums;
    std::vector<std::unique_ptr<Union>> unions;
    
    /**
     * @brief Find struct by name
     */
    [[nodiscard]] const Struct* find_struct(const std::string& name) const noexcept {
        for (const auto& s : structs) {
            if (s->name == name) return s.get();
        }
        return nullptr;
    }
    
    /**
     * @brief Find enum by name
     */
    [[nodiscard]] const Enum* find_enum(const std::string& name) const noexcept {
        for (const auto& e : enums) {
            if (e->name == name) return e.get();
        }
        return nullptr;
    }
    
    /**
     * @brief Find union by name
     */
    [[nodiscard]] const Union* find_union(const std::string& name) const noexcept {
        for (const auto& u : unions) {
            if (u->name == name) return u.get();
        }
        return nullptr;
    }
};

} // namespace psyc