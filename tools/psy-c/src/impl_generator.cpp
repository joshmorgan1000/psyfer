/**
 * @file impl_generator.cpp
 * @brief Implementation generator for psy-c generated code
 */

#include "psy-c/impl_generator.hpp"
#include <algorithm>
#include <cctype>

namespace psyc {

std::string ImplGenerator::generate(const Schema& schema, const GeneratorOptions& options) {
    ImplGenerator gen(schema, options);
    return gen.generate_code();
}

ImplGenerator::ImplGenerator(const Schema& schema, const GeneratorOptions& options)
    : schema_(schema), options_(options) {}

std::string ImplGenerator::generate_code() {
    generate_header();
    generate_includes();
    generate_namespace_begin();
    generate_struct_impls();
    generate_namespace_end();
    
    return output_.str();
}

void ImplGenerator::generate_header() {
    emit_line("/**");
    emit_line(" * @file generated_impl.cpp");
    emit_line(" * @brief Implementation for psy-c generated code");
    emit_line(" * @warning This file is auto-generated. Do not edit manually.");
    emit_line(" */");
    emit_line();
}

void ImplGenerator::generate_includes() {
    // Include the corresponding header file
    if (!options_.output_header_file.empty()) {
        emit_line("#include \"" + options_.output_header_file + "\"");
    } else {
        emit_line("#include \"generated.hpp\"");
    }
    emit_line("#include <psyfer.hpp>");
    emit_line();
}

void ImplGenerator::generate_namespace_begin() {
    if (!options_.namespace_prefix.empty()) {
        emit_line("namespace " + options_.namespace_prefix + " {");
    }
    
    if (schema_.namespace_decl) {
        for (const auto& component : (*schema_.namespace_decl)->components) {
            emit_line("namespace " + component + " {");
        }
    }
    
    emit_line();
}

void ImplGenerator::generate_namespace_end() {
    if (schema_.namespace_decl) {
        for (size_t i = 0; i < (*schema_.namespace_decl)->components.size(); ++i) {
            emit_line("} // namespace " + (*schema_.namespace_decl)->components[
                (*schema_.namespace_decl)->components.size() - 1 - i]);
        }
    }
    
    if (!options_.namespace_prefix.empty()) {
        emit_line("} // namespace " + options_.namespace_prefix);
    }
}

void ImplGenerator::generate_struct_impls() {
    for (const auto& st : schema_.structs) {
        generate_struct_impl(*st);
        emit_line();
    }
}

void ImplGenerator::generate_struct_impl(const Struct& st) {
    generate_serialization_impl(st);
    generate_deserialization_impl(st);
    
    if (st.has_annotation("encrypt") || has_encrypted_fields(st)) {
        generate_encryption_impl(st);
    }
    
    if (st.has_annotation("compress") || has_compressed_fields(st)) {
        generate_compression_impl(st);
    }
    
    if (st.has_annotation("sign")) {
        generate_signing_impl(st);
    }
}

void ImplGenerator::generate_serialization_impl(const Struct& st) {
    using namespace std::string_literals;
    
    // Size calculation
    emit_line("size_t " + st.name + "::serialized_size() const noexcept {");
    indent();
    emit_line("using namespace psyfer::serialization;");
    emit_line("size_t size = 0;");
    emit_line();
    
    for (size_t i = 0; i < st.fields.size(); ++i) {
        const auto& field = st.fields[i];
        std::string field_num = std::to_string(i + 1);
        
        if (field->type.is_primitive()) {
            auto prim_type = std::get<PrimitiveType>(field->type.kind);
            switch (prim_type) {
                case PrimitiveType::BOOL:
                case PrimitiveType::INT8:
                case PrimitiveType::INT16:
                case PrimitiveType::INT32:
                case PrimitiveType::INT64:
                case PrimitiveType::UINT8:
                case PrimitiveType::UINT16:
                case PrimitiveType::UINT32:
                case PrimitiveType::UINT64:
                    emit_line("size += field_header_size(" + field_num + ") + " +
                            "varint_size(" + field->name + ");");
                    break;
                case PrimitiveType::FLOAT32:
                    emit_line("size += field_header_size(" + field_num + ") + 4;");
                    break;
                case PrimitiveType::FLOAT64:
                    emit_line("size += field_header_size(" + field_num + ") + 8;");
                    break;
                case PrimitiveType::BYTES:
                    if (field->type.optional) {
                        emit_line("if (" + field->name + ") {");
                        indent();
                        emit_line("size += field_header_size(" + field_num + ") + " +
                                "bytes_field_size(" + field->name + "->size());");
                        dedent();
                        emit_line("}");
                    } else {
                        emit_line("size += field_header_size(" + field_num + ") + " +
                                "bytes_field_size(" + field->name + ".size());");
                    }
                    break;
                case PrimitiveType::TEXT:
                    if (field->type.optional) {
                        emit_line("if (" + field->name + ") {");
                        indent();
                        emit_line("size += field_header_size(" + field_num + ") + " +
                                "string_field_size(*" + field->name + ");");
                        dedent();
                        emit_line("}");
                    } else {
                        emit_line("size += field_header_size(" + field_num + ") + " +
                                "string_field_size(" + field->name + ");");
                    }
                    break;
            }
        }
        
        // Optional handling is implemented within each type's case above
    }
    
    emit_line("return size;");
    dedent();
    emit_line("}");
    emit_line();
    
    // Serialize implementation
    emit_line("size_t " + st.name + "::serialize(std::span<std::byte> buffer) const noexcept {");
    indent();
    emit_line("using namespace psyfer::serialization;");
    emit_line("BufferWriter writer(buffer);");
    emit_line();
    
    for (size_t i = 0; i < st.fields.size(); ++i) {
        const auto& field = st.fields[i];
        std::string field_num = std::to_string(i + 1);
        
        if (field->type.is_primitive()) {
            auto prim_type = std::get<PrimitiveType>(field->type.kind);
            
            // Write field header
            switch (prim_type) {
                case PrimitiveType::BOOL:
                case PrimitiveType::INT8:
                case PrimitiveType::INT16:
                case PrimitiveType::INT32:
                case PrimitiveType::INT64:
                case PrimitiveType::UINT8:
                case PrimitiveType::UINT16:
                case PrimitiveType::UINT32:
                case PrimitiveType::UINT64:
                    emit_line("writer.write_field_header(" + field_num + ", WireType::VARINT);");
                    break;
                case PrimitiveType::FLOAT32:
                    emit_line("writer.write_field_header(" + field_num + ", WireType::FIXED32);");
                    break;
                case PrimitiveType::FLOAT64:
                    emit_line("writer.write_field_header(" + field_num + ", WireType::FIXED64);");
                    break;
                case PrimitiveType::BYTES:
                case PrimitiveType::TEXT:
                    if (field->type.optional) {
                        emit_line("if (" + field->name + ") {");
                        indent();
                    }
                    emit_line("writer.write_field_header(" + field_num + ", WireType::BYTES);");
                    break;
            }
            
            // For non-bytes/text optional fields, wrap here
            if (field->type.optional && 
                prim_type != PrimitiveType::BYTES && 
                prim_type != PrimitiveType::TEXT) {
                emit_line("if (" + field->name + ") {");
                indent();
            }
            
            // Write value
            std::string deref = field->type.optional ? "*" : "";
            switch (prim_type) {
                case PrimitiveType::BOOL:
                    emit_line("writer.write_varint(" + deref + field->name + " ? 1 : 0);");
                    break;
                case PrimitiveType::INT8:
                case PrimitiveType::INT16:
                case PrimitiveType::INT32:
                case PrimitiveType::INT64:
                    emit_line("writer.write_signed_varint(" + deref + field->name + ");");
                    break;
                case PrimitiveType::UINT8:
                case PrimitiveType::UINT16:
                case PrimitiveType::UINT32:
                case PrimitiveType::UINT64:
                    emit_line("writer.write_varint(" + deref + field->name + ");");
                    break;
                case PrimitiveType::FLOAT32:
                    emit_line("writer.write_f32(" + deref + field->name + ");");
                    break;
                case PrimitiveType::FLOAT64:
                    emit_line("writer.write_f64(" + deref + field->name + ");");
                    break;
                case PrimitiveType::BYTES:
                    emit_line("writer.write_bytes_field(" + deref + field->name + ");");
                    break;
                case PrimitiveType::TEXT:
                    emit_line("writer.write_string_field(" + deref + field->name + ");");
                    break;
            }
            
            if (field->type.optional) {
                dedent();
                emit_line("}");
            }
        }
        
        emit_line();
    }
    
    emit_line("return writer.position();");
    dedent();
    emit_line("}");
}

void ImplGenerator::generate_deserialization_impl(const Struct& st) {
    // Generate serialize() that returns vector
    emit_line();
    emit_line("std::vector<std::byte> " + st.name + "::serialize() const {");
    indent();
    emit_line("std::vector<std::byte> buffer(serialized_size());");
    emit_line("serialize(buffer);");
    emit_line("return buffer;");
    dedent();
    emit_line("}");
    
    // Generate static deserialize method
    emit_line();
    emit_line("std::optional<" + st.name + "> " + st.name + "::deserialize(");
    indent();
    emit_line("std::span<const std::byte> buffer");
    dedent();
    emit_line(") noexcept {");
    indent();
    emit_line("using namespace psyfer::serialization;");
    emit_line("BufferReader reader(buffer);");
    emit_line(st.name + " result;");
    emit_line();
    
    // Read each field
    for (size_t i = 0; i < st.fields.size(); ++i) {
        const auto& field = st.fields[i];
        std::string field_num = std::to_string(i + 1);
        
        if (field->type.is_primitive()) {
            auto prim_type = std::get<PrimitiveType>(field->type.kind);
            
            // Read field header
            emit_line("// Field " + field_num + ": " + field->name);
            emit_line("auto header" + field_num + " = reader.read_field_header();");
            emit_line("if (!header" + field_num + " || header" + field_num + "->field_number != " + 
                     field_num + ") {");
            indent();
            
            if (field->type.optional) {
                emit_line("// Optional field, skip if not present");
                emit_line("result." + field->name + " = std::nullopt;");
            } else {
                emit_line("return std::nullopt; // Required field missing");
            }
            
            dedent();
            emit_line("} else {");
            indent();
            
            // Read value based on type
            switch (prim_type) {
                case PrimitiveType::BOOL:
                    emit_line("auto val = reader.read_varint();");
                    emit_line("if (!val) return std::nullopt;");
                    if (field->type.optional) {
                        emit_line("result." + field->name + " = (*val != 0);");
                    } else {
                        emit_line("result." + field->name + " = (*val != 0);");
                    }
                    break;
                    
                case PrimitiveType::INT8:
                case PrimitiveType::INT16:
                case PrimitiveType::INT32:
                case PrimitiveType::INT64:
                    emit_line("auto val = reader.read_signed_varint();");
                    emit_line("if (!val) return std::nullopt;");
                    if (field->type.optional) {
                        emit_line("result." + field->name + " = static_cast<" + 
                                 primitive_type_name(prim_type) + ">(*val);");
                    } else {
                        emit_line("result." + field->name + " = static_cast<" + 
                                 primitive_type_name(prim_type) + ">(*val);");
                    }
                    break;
                    
                case PrimitiveType::UINT8:
                case PrimitiveType::UINT16:
                case PrimitiveType::UINT32:
                case PrimitiveType::UINT64:
                    emit_line("auto val = reader.read_varint();");
                    emit_line("if (!val) return std::nullopt;");
                    if (field->type.optional) {
                        emit_line("result." + field->name + " = static_cast<" + 
                                 primitive_type_name(prim_type) + ">(*val);");
                    } else {
                        emit_line("result." + field->name + " = static_cast<" + 
                                 primitive_type_name(prim_type) + ">(*val);");
                    }
                    break;
                    
                case PrimitiveType::FLOAT32:
                    emit_line("auto val = reader.read_f32();");
                    emit_line("if (!val) return std::nullopt;");
                    if (field->type.optional) {
                        emit_line("result." + field->name + " = *val;");
                    } else {
                        emit_line("result." + field->name + " = *val;");
                    }
                    break;
                    
                case PrimitiveType::FLOAT64:
                    emit_line("auto val = reader.read_f64();");
                    emit_line("if (!val) return std::nullopt;");
                    if (field->type.optional) {
                        emit_line("result." + field->name + " = *val;");
                    } else {
                        emit_line("result." + field->name + " = *val;");
                    }
                    break;
                    
                case PrimitiveType::BYTES:
                    emit_line("auto val = reader.read_bytes_field();");
                    emit_line("if (!val) return std::nullopt;");
                    if (field->type.optional) {
                        emit_line("result." + field->name + " = std::vector<std::byte>(val->begin(), val->end());");
                    } else {
                        emit_line("result." + field->name + ".assign(val->begin(), val->end());");
                    }
                    break;
                    
                case PrimitiveType::TEXT:
                    emit_line("auto val = reader.read_string_field();");
                    emit_line("if (!val) return std::nullopt;");
                    if (field->type.optional) {
                        emit_line("result." + field->name + " = *val;");
                    } else {
                        emit_line("result." + field->name + " = *val;");
                    }
                    break;
            }
            
            dedent();
            emit_line("}");
            emit_line();
        }
    }
    
    emit_line("return result;");
    dedent();
    emit_line("}");
    
    // Generate zero-copy deserialize method
    emit_line();
    emit_line("size_t " + st.name + "::deserialize(");
    indent();
    emit_line("std::span<const std::byte> source_buffer,");
    emit_line(st.name + "* target");
    dedent();
    emit_line(") noexcept {");
    indent();
    emit_line("auto result = deserialize(source_buffer);");
    emit_line("if (!result) return 0;");
    emit_line("*target = std::move(*result);");
    emit_line("return source_buffer.size();");
    dedent();
    emit_line("}");
}

void ImplGenerator::generate_encryption_impl(const Struct& st) {
    // Determine encryption algorithm
    std::string algo = get_encryption_algorithm(st);
    
    emit_line();
    emit_line("// Encryption implementation");
    
    // encrypted_size
    emit_line("size_t " + st.name + "::encrypted_size() const noexcept {");
    indent();
    
    if (algo == "aes256" || algo == "aes256_gcm") {
        emit_line("// AES-256-GCM: serialized + nonce(12) + tag(16)");
        emit_line("return serialized_size() + 12 + 16;");
    } else if (algo == "chacha20" || algo == "chacha20_poly1305") {
        emit_line("// ChaCha20-Poly1305: serialized + nonce(12) + tag(16)");
        emit_line("return serialized_size() + 12 + 16;");
    } else {
        emit_line("// Default: assume AEAD with 12-byte nonce, 16-byte tag");
        emit_line("return serialized_size() + 28;");
    }
    
    dedent();
    emit_line("}");
    emit_line();
    
    // encrypt method
    emit_line("size_t " + st.name + "::encrypt(");
    indent();
    emit_line("std::span<std::byte> buffer,");
    emit_line("std::span<const std::byte> key");
    dedent();
    emit_line(") const noexcept {");
    indent();
    
    emit_line("// Layout: [nonce:12][encrypted_data][tag:16]");
    emit_line();
    
    emit_line("// Generate nonce");
    emit_line("auto nonce = buffer.subspan(0, 12);");
    emit_line("psyfer::utils::secure_random::generate(nonce);");
    emit_line();
    
    emit_line("// Serialize to position after nonce");
    emit_line("auto data_start = buffer.subspan(12);");
    emit_line("size_t serialized_size = serialize(data_start);");
    emit_line();
    
    emit_line("// Encrypt in-place");
    emit_line("auto tag = buffer.subspan(12 + serialized_size, 16);");
    
    if (algo == "aes256" || algo == "aes256_gcm") {
        emit_line("auto result = psyfer::crypto::aes256_gcm::encrypt_oneshot(");
        indent();
        emit_line("data_start.subspan(0, serialized_size),");
        emit_line("std::span<const std::byte, 32>(key.data(), 32),");
        emit_line("std::span<const std::byte, 12>(nonce.data(), 12),");
        emit_line("std::span<std::byte, 16>(tag.data(), 16),");
        emit_line("{}  // no AAD");
        dedent();
        emit_line(");");
    } else if (algo == "chacha20" || algo == "chacha20_poly1305") {
        emit_line("psyfer::crypto::chacha20_poly1305 cipher;");
        emit_line("auto result = cipher.encrypt(");
        indent();
        emit_line("data_start.subspan(0, serialized_size),");
        emit_line("std::span<const std::byte>(key.data(), 32),");
        emit_line("std::span<const std::byte>(nonce.data(), 12),");
        emit_line("std::span<std::byte>(tag.data(), 16),");
        emit_line("{}  // no AAD");
        dedent();
        emit_line(");");
    }
    
    emit_line();
    emit_line("if (result) {");
    indent();
    emit_line("return 0;");
    dedent();
    emit_line("}");
    emit_line();
    emit_line("return 12 + serialized_size + 16;");
    
    dedent();
    emit_line("}");
    emit_line();
    
    // decrypt method
    emit_line("std::optional<" + st.name + "> " + st.name + "::decrypt(");
    indent();
    emit_line("std::span<const std::byte> buffer,");
    emit_line("std::span<const std::byte> key");
    dedent();
    emit_line(") noexcept {");
    indent();
    
    emit_line("if (buffer.size() < 28) return std::nullopt;  // min size");
    emit_line();
    
    emit_line("// Extract components");
    emit_line("auto nonce = buffer.subspan(0, 12);");
    emit_line("auto tag = buffer.subspan(buffer.size() - 16, 16);");
    emit_line("auto encrypted = buffer.subspan(12, buffer.size() - 28);");
    emit_line();
    
    emit_line("// Decrypt to temporary buffer");
    emit_line("std::vector<std::byte> decrypted(encrypted.size());");
    emit_line("std::memcpy(decrypted.data(), encrypted.data(), encrypted.size());");
    emit_line();
    
    if (algo == "aes256" || algo == "aes256_gcm") {
        emit_line("auto result = psyfer::crypto::aes256_gcm::decrypt_oneshot(");
        indent();
        emit_line("decrypted,");
        emit_line("std::span<const std::byte, 32>(key.data(), 32),");
        emit_line("std::span<const std::byte, 12>(nonce.data(), 12),");
        emit_line("std::span<const std::byte, 16>(tag.data(), 16),");
        emit_line("{}  // no AAD");
        dedent();
        emit_line(");");
    } else if (algo == "chacha20" || algo == "chacha20_poly1305") {
        emit_line("psyfer::crypto::chacha20_poly1305 cipher;");
        emit_line("auto result = cipher.decrypt(");
        indent();
        emit_line("decrypted,");
        emit_line("std::span<const std::byte>(key.data(), 32),");
        emit_line("std::span<const std::byte>(nonce.data(), 12),");
        emit_line("std::span<const std::byte>(tag.data(), 16),");
        emit_line("{}  // no AAD");
        dedent();
        emit_line(");");
    }
    
    emit_line();
    emit_line("if (result) {");
    indent();
    emit_line("return std::nullopt;");
    dedent();
    emit_line("}");
    emit_line();
    
    emit_line("// Deserialize decrypted data");
    emit_line("return deserialize(decrypted);");
    
    dedent();
    emit_line("}");
}

void ImplGenerator::generate_compression_impl(const Struct& st) {
    // Determine compression algorithm
    std::string algo = get_compression_algorithm(st);
    
    emit_line();
    emit_line("// Compression implementation");
    
    // compressed_size
    emit_line("size_t " + st.name + "::compressed_size() const noexcept {");
    indent();
    
    if (algo == "lz4") {
        emit_line("// LZ4: worst case is slightly larger than input");
        emit_line("size_t input_size = serialized_size();");
        emit_line("return input_size + (input_size/255) + 16;");
    } else if (algo == "fpc") {
        emit_line("// FPC: worst case for floating point compression");
        emit_line("return serialized_size() + serialized_size() / 8 + 16;");
    } else {
        emit_line("// Default: assume 2x expansion worst case");
        emit_line("return serialized_size() * 2;");
    }
    
    dedent();
    emit_line("}");
    emit_line();
    
    // compress method
    emit_line("size_t " + st.name + "::compress(");
    indent();
    emit_line("std::span<std::byte> buffer");
    dedent();
    emit_line(") const noexcept {");
    indent();
    
    emit_line("// Serialize first");
    emit_line("std::vector<std::byte> serialized(serialized_size());");
    emit_line("size_t serialized_len = serialize(serialized);");
    emit_line();
    
    if (algo == "lz4") {
        emit_line("// Compress with LZ4");
        emit_line("psyfer::compression::lz4 compressor;");
        emit_line("auto result = compressor.compress(");
        indent();
        emit_line("std::span(serialized.data(), serialized_len),");
        emit_line("buffer");
        dedent();
        emit_line(");");
        emit_line("return result ? *result : 0;");
    } else if (algo == "fpc") {
        emit_line("// FPC is for floating point data compression");
        emit_line("// TODO: Field-level FPC compression is not yet implemented");
        emit_line("// For now, using LZ4 as a fallback for all compression");
        emit_line("psyfer::compression::lz4 compressor;");
        emit_line("auto result = compressor.compress(");
        indent();
        emit_line("std::span(serialized.data(), serialized_len),");
        emit_line("buffer");
        dedent();
        emit_line(");");
        emit_line("return result ? *result : 0;");
    } else {
        emit_line("// Unsupported compression algorithm: " + algo);
        emit_line("static_assert(false, \"Unsupported compression algorithm\");");
        emit_line("return 0;");
    }
    
    dedent();
    emit_line("}");
    emit_line();
    
    // compress to vector method
    emit_line("std::vector<std::byte> " + st.name + "::compress() const {");
    indent();
    emit_line("std::vector<std::byte> result(compressed_size());");
    emit_line("size_t compressed_len = compress(result);");
    emit_line("result.resize(compressed_len);");
    emit_line("return result;");
    dedent();
    emit_line("}");
    emit_line();
    
    // decompress method
    emit_line("std::optional<" + st.name + "> " + st.name + "::decompress(");
    indent();
    emit_line("std::span<const std::byte> buffer");
    dedent();
    emit_line(") noexcept {");
    indent();
    
    emit_line("// Allocate decompression buffer");
    emit_line("std::vector<std::byte> decompressed;");
    emit_line();
    
    if (algo == "lz4") {
        emit_line("// Decompress with LZ4");
        emit_line("// First, try to determine uncompressed size");
        emit_line("psyfer::compression::lz4 decompressor;");
        emit_line("// Allocate a reasonable buffer (assume 10x expansion)");
        emit_line("decompressed.resize(buffer.size() * 10);");
        emit_line("auto result = decompressor.decompress(buffer, decompressed);");
        emit_line("if (!result) return std::nullopt;");
        emit_line("decompressed.resize(*result);");
    } else if (algo == "fpc") {
        emit_line("// FPC decompression (falling back to LZ4 for struct-level)");
        emit_line("psyfer::compression::lz4 decompressor;");
        emit_line("// First, allocate a reasonable buffer");
        emit_line("decompressed.resize(buffer.size() * 10);");
        emit_line("auto result = decompressor.decompress(buffer, decompressed);");
        emit_line("if (result) {");
        emit_line("    decompressed.resize(*result);");
        emit_line("} else {");
        emit_line("    return std::nullopt;");
        emit_line("}");
    } else {
        emit_line("// Unsupported compression algorithm: " + algo);
        emit_line("static_assert(false, \"Unsupported compression algorithm\");");
        emit_line("return std::nullopt;");
    }
    
    emit_line();
    emit_line("// Deserialize decompressed data");
    emit_line("return deserialize(decompressed);");
    
    dedent();
    emit_line("}");
    emit_line();
    
    // decompress to target method
    emit_line("size_t " + st.name + "::decompress(");
    indent();
    emit_line("std::span<const std::byte> source_buffer,");
    emit_line(st.name + "* target");
    dedent();
    emit_line(") noexcept {");
    indent();
    
    emit_line("auto result = decompress(source_buffer);");
    emit_line("if (!result) return 0;");
    emit_line("*target = std::move(*result);");
    emit_line("return 1;  // Success");
    
    dedent();
    emit_line("}");
}

void ImplGenerator::generate_signing_impl(const Struct& st) {
    emit_line();
    emit_line("// Digital signature implementation");
    
    // sign method
    emit_line("std::array<std::byte, 64> " + st.name + "::sign(");
    indent();
    emit_line("std::span<const std::byte, 32> private_key");
    dedent();
    emit_line(") const noexcept {");
    indent();
    
    emit_line("// Serialize the message (or signed fields only)");
    emit_line("std::vector<std::byte> data(serialized_size());");
    emit_line("serialize(data);");
    emit_line();
    
    emit_line("// Sign the serialized data");
    emit_line("std::array<std::byte, 64> signature;");
    emit_line("psyfer::crypto::ed25519::sign(");
    indent();
    emit_line("data,");
    emit_line("std::span<const std::byte, 32>(private_key.data(), 32),");
    emit_line("std::span<std::byte, 64>(signature.data(), 64)");
    dedent();
    emit_line(");");
    emit_line();
    emit_line("return signature;");
    
    dedent();
    emit_line("}");
    emit_line();
    
    // verify method
    emit_line("bool " + st.name + "::verify(");
    indent();
    emit_line("const " + st.name + "& message,");
    emit_line("std::span<const std::byte, 64> signature,");
    emit_line("std::span<const std::byte, 32> public_key");
    dedent();
    emit_line(") noexcept {");
    indent();
    
    emit_line("// Serialize the message");
    emit_line("std::vector<std::byte> data(message.serialized_size());");
    emit_line("message.serialize(data);");
    emit_line();
    
    emit_line("// Verify the signature");
    emit_line("return psyfer::crypto::ed25519::verify(");
    indent();
    emit_line("data,");
    emit_line("std::span<const std::byte, 64>(signature.data(), 64),");
    emit_line("std::span<const std::byte, 32>(public_key.data(), 32)");
    dedent();
    emit_line(");");
    
    dedent();
    emit_line("}");
    emit_line();
    
    // sign_and_serialize method
    emit_line("std::vector<std::byte> " + st.name + "::sign_and_serialize(");
    indent();
    emit_line("std::span<const std::byte, 32> private_key");
    dedent();
    emit_line(") const {");
    indent();
    
    emit_line("// Layout: [signature:64][serialized_data]");
    emit_line("size_t total_size = 64 + serialized_size();");
    emit_line("std::vector<std::byte> result(total_size);");
    emit_line();
    
    emit_line("// Serialize first");
    emit_line("auto data_span = std::span(result).subspan(64);");
    emit_line("serialize(data_span);");
    emit_line();
    
    emit_line("// Sign the serialized data");
    emit_line("psyfer::crypto::ed25519::sign(");
    indent();
    emit_line("data_span,");
    emit_line("std::span<const std::byte, 32>(private_key.data(), 32),");
    emit_line("std::span<std::byte, 64>(result.data(), 64)");
    dedent();
    emit_line(");");
    emit_line();
    emit_line("return result;");
    
    dedent();
    emit_line("}");
    emit_line();
    
    // verify_and_deserialize method
    emit_line("std::optional<" + st.name + "> " + st.name + "::verify_and_deserialize(");
    indent();
    emit_line("std::span<const std::byte> signed_data,");
    emit_line("std::span<const std::byte, 32> public_key");
    dedent();
    emit_line(") noexcept {");
    indent();
    
    emit_line("if (signed_data.size() < 64) return std::nullopt;");
    emit_line();
    
    emit_line("// Extract signature and data");
    emit_line("auto signature = signed_data.subspan(0, 64);");
    emit_line("auto data = signed_data.subspan(64);");
    emit_line();
    
    emit_line("// Verify signature");
    emit_line("bool valid = psyfer::crypto::ed25519::verify(");
    indent();
    emit_line("data,");
    emit_line("std::span<const std::byte, 64>(signature.data(), 64),");
    emit_line("std::span<const std::byte, 32>(public_key.data(), 32)");
    dedent();
    emit_line(");");
    emit_line();
    emit_line("if (!valid) return std::nullopt;");
    emit_line();
    
    emit_line("// Deserialize if valid");
    emit_line("return deserialize(data);");
    
    dedent();
    emit_line("}");
}

std::string ImplGenerator::get_encryption_algorithm(const Field& field) const {
    auto ann = field.get_annotation("encrypt");
    if (!ann) return "aes256";
    
    auto algo = ann->get_parameter("algorithm");
    return algo.value_or("aes256");
}

std::string ImplGenerator::get_encryption_algorithm(const Struct& st) const {
    auto ann = st.get_annotation("encrypt");
    if (!ann) {
        // Check if any field is encrypted and use that algorithm
        for (const auto& field : st.fields) {
            if (field->has_annotation("encrypt")) {
                return get_encryption_algorithm(*field);
            }
        }
        return "aes256";
    }
    
    auto algo = ann->get_parameter("algorithm");
    return algo.value_or("aes256");
}

std::string ImplGenerator::get_compression_algorithm(const Struct& st) const {
    auto ann = st.get_annotation("compress");
    if (!ann) {
        // Check if any field is compressed and use that algorithm
        for (const auto& field : st.fields) {
            if (field->has_annotation("compress")) {
                return get_compression_algorithm(*field);
            }
        }
        return "lz4";
    }
    
    auto algo = ann->get_parameter("algorithm");
    return algo.value_or("lz4");
}

std::string ImplGenerator::get_compression_algorithm(const Field& field) const {
    auto ann = field.get_annotation("compress");
    if (!ann) return "lz4";
    
    auto algo = ann->get_parameter("algorithm");
    return algo.value_or("lz4");
}

bool ImplGenerator::has_encrypted_fields(const Struct& st) const {
    for (const auto& field : st.fields) {
        if (field->has_annotation("encrypt")) {
            return true;
        }
    }
    return false;
}

bool ImplGenerator::has_compressed_fields(const Struct& st) const {
    for (const auto& field : st.fields) {
        if (field->has_annotation("compress")) {
            return true;
        }
    }
    return false;
}

void ImplGenerator::emit(const std::string& text) {
    output_ << text;
}

void ImplGenerator::emit_line(const std::string& text) {
    for (size_t i = 0; i < indent_level_; ++i) {
        output_ << "    ";
    }
    output_ << text << "\n";
}

void ImplGenerator::indent() {
    indent_level_++;
}

void ImplGenerator::dedent() {
    if (indent_level_ > 0) {
        indent_level_--;
    }
}

std::string ImplGenerator::primitive_type_name(PrimitiveType type) const {
    switch (type) {
        case PrimitiveType::BOOL: return "bool";
        case PrimitiveType::INT8: return "int8_t";
        case PrimitiveType::INT16: return "int16_t";
        case PrimitiveType::INT32: return "int32_t";
        case PrimitiveType::INT64: return "int64_t";
        case PrimitiveType::UINT8: return "uint8_t";
        case PrimitiveType::UINT16: return "uint16_t";
        case PrimitiveType::UINT32: return "uint32_t";
        case PrimitiveType::UINT64: return "uint64_t";
        case PrimitiveType::FLOAT32: return "float";
        case PrimitiveType::FLOAT64: return "double";
        case PrimitiveType::BYTES: return "std::vector<std::byte>";
        case PrimitiveType::TEXT: return "std::string";
    }
    return "unknown";
}

} // namespace psyc