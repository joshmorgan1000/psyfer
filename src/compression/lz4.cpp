/**
 * @file lz4.cpp
 * @brief LZ4 compression implementation
 */

#include <psyfer.hpp>
#include <cstring>
#include <algorithm>
#include <bit>

namespace psyfer::compression {

// ────────────────────────────────────────────────────────────────────────────
// Helper for 64-bit reads
// ────────────────────────────────────────────────────────────────────────────

static uint64_t read64(const uint8_t* ptr) noexcept {
    uint64_t val;
    std::memcpy(&val, ptr, sizeof(val));
    #ifdef __BIG_ENDIAN__
        val = __builtin_bswap64(val);
    #endif
    return val;
}

// ────────────────────────────────────────────────────────────────────────────
// LZ4 Helper Functions
// ────────────────────────────────────────────────────────────────────────────

size_t lz4::count_match(
    const uint8_t* pIn,
    const uint8_t* pMatch,
    const uint8_t* pInLimit
) noexcept {
    const uint8_t* const pStart = pIn;
    
    // Fast path: compare 64-bit at a time if possible
    while (pIn + 8 <= pInLimit) {
        uint64_t diff = read64(pIn) ^ read64(pMatch);
        if (diff != 0) {
            // Find first differing byte
            return pIn - pStart + (__builtin_ctzll(diff) >> 3);
        }
        pIn += 8;
        pMatch += 8;
    }
    
    // Slow path: byte by byte
    while ((pIn < pInLimit) && (*pIn == *pMatch)) {
        pIn++;
        pMatch++;
    }
    
    return pIn - pStart;
}

uint8_t* lz4::write_length(
    uint8_t* op,
    size_t length,
    uint8_t* token,
    bool is_literal
) noexcept {
    if (is_literal) {
        // Literal length
        if (length < 15) {
            *token = static_cast<uint8_t>(length << ML_BITS);
        } else {
            *token = static_cast<uint8_t>(RUN_MASK << ML_BITS);
            length -= RUN_MASK;
            while (length >= 255) {
                *op++ = 255;
                length -= 255;
            }
            *op++ = static_cast<uint8_t>(length);
        }
    } else {
        // Match length
        if (length < 15) {
            *token |= static_cast<uint8_t>(length);
        } else {
            *token |= ML_MASK;
            length -= ML_MASK;
            while (length >= 255) {
                *op++ = 255;
                length -= 255;
            }
            *op++ = static_cast<uint8_t>(length);
        }
    }
    return op;
}

void lz4::wild_copy(uint8_t* dst, const uint8_t* src, uint8_t* dst_end) noexcept {
    // Copy 8 bytes at a time for speed
    do {
        std::memcpy(dst, src, 8);
        dst += 8;
        src += 8;
    } while (dst < dst_end);
}

// ────────────────────────────────────────────────────────────────────────────
// LZ4 Compression
// ────────────────────────────────────────────────────────────────────────────

size_t lz4::max_compressed_size(size_t uncompressed_size) const noexcept {
    // LZ4 worst case: input_size + (input_size/255) + 16
    return uncompressed_size + (uncompressed_size / 255) + 16;
}

result<size_t> lz4::compress(
    std::span<const std::byte> input,
    std::span<std::byte> output
) noexcept {
    return compress_fast(input, output, 1);
}

result<size_t> lz4::compress_fast(
    std::span<const std::byte> input,
    std::span<std::byte> output,
    int acceleration
) noexcept {
    if (output.size() < max_compressed_size(input.size())) {
        return std::unexpected(make_error_code(error_code::invalid_buffer_size));
    }
    
    const uint8_t* ip = reinterpret_cast<const uint8_t*>(input.data());
    const uint8_t* const iend = ip + input.size();
    const uint8_t* const mflimit = iend - MFLIMIT;
    const uint8_t* const matchlimit = iend - LAST_LITERAL_SIZE;
    
    uint8_t* op = reinterpret_cast<uint8_t*>(output.data());
    uint8_t* token;
    
    // Hash table for finding matches
    const size_t hash_log = 12;  // 4KB hash table
    size_t hash_table[1 << hash_log] = {0};
    
    // Acceleration
    acceleration = std::max(1, acceleration);
    
    // Special case: empty input
    if (input.empty()) {
        return 0;
    }
    
    // First byte is always literal
    const uint8_t* anchor = ip;
    
    // Main compression loop
    while (ip < mflimit) {
        const uint8_t* match;
        
        // Find a match
        uint32_t h = hash4(ip, hash_log);
        size_t ref = hash_table[h];
        hash_table[h] = ip - reinterpret_cast<const uint8_t*>(input.data());
        match = reinterpret_cast<const uint8_t*>(input.data()) + ref;
        
        // Skip forward until we find a match
        if (ref == 0 || match + MIN_MATCH > ip || read32(match) != read32(ip)) {
            ip++;
            continue;
        }
        
        // Encode literal run
        const size_t literal_length = ip - anchor;
        token = op++;
        
        if (literal_length >= RUN_MASK) {
            *token = RUN_MASK << ML_BITS;
            size_t len = literal_length - RUN_MASK;
            while (len >= 255) {
                *op++ = 255;
                len -= 255;
            }
            *op++ = static_cast<uint8_t>(len);
        } else {
            *token = static_cast<uint8_t>(literal_length << ML_BITS);
        }
        
        // Copy literals
        std::memcpy(op, anchor, literal_length);
        op += literal_length;
        
        // Encode offset
        write16(op, static_cast<uint16_t>(ip - match));
        op += 2;
        
        // Encode match length
        ip += MIN_MATCH;
        match += MIN_MATCH;
        const size_t match_length = count_match(ip, match, matchlimit);
        ip += match_length;
        
        if (match_length >= ML_MASK) {
            *token |= ML_MASK;
            size_t len = match_length - ML_MASK;
            while (len >= 255) {
                *op++ = 255;
                len -= 255;
            }
            *op++ = static_cast<uint8_t>(len);
        } else {
            *token |= static_cast<uint8_t>(match_length);
        }
        
        anchor = ip;
    }
    
    // Encode last literals
    const size_t last_literals = iend - anchor;
    if (last_literals >= RUN_MASK) {
        *op++ = RUN_MASK << ML_BITS;
        size_t len = last_literals - RUN_MASK;
        while (len >= 255) {
            *op++ = 255;
            len -= 255;
        }
        *op++ = static_cast<uint8_t>(len);
    } else {
        *op++ = static_cast<uint8_t>(last_literals << ML_BITS);
    }
    std::memcpy(op, anchor, last_literals);
    op += last_literals;
    
    return op - reinterpret_cast<uint8_t*>(output.data());
}

// ────────────────────────────────────────────────────────────────────────────
// LZ4 Decompression
// ────────────────────────────────────────────────────────────────────────────

result<size_t> lz4::decompress(
    std::span<const std::byte> input,
    std::span<std::byte> output
) noexcept {
    const uint8_t* ip = reinterpret_cast<const uint8_t*>(input.data());
    const uint8_t* const iend = ip + input.size();
    
    uint8_t* op = reinterpret_cast<uint8_t*>(output.data());
    uint8_t* const oend = op + output.size();
    uint8_t* cpy;
    
    // Main decompression loop
    while (ip < iend) {
        // Get token
        const uint8_t token = *ip++;
        size_t literal_length = token >> ML_BITS;
        
        // Decode literal length
        if (literal_length == RUN_MASK) {
            uint8_t s;
            do {
                if (ip >= iend) {
                    return std::unexpected(make_error_code(error_code::decompression_failed));
                }
                s = *ip++;
                literal_length += s;
            } while (s == 255);
        }
        
        // Copy literals
        cpy = op + literal_length;
        if (cpy > oend || ip + literal_length > iend) {
            return std::unexpected(make_error_code(error_code::invalid_buffer_size));
        }
        std::memcpy(op, ip, literal_length);
        ip += literal_length;
        op = cpy;
        
        // Check for end of input
        if (ip >= iend) break;
        
        // Decode match
        uint16_t offset = read16(ip);
        ip += 2;
        const uint8_t* match = op - offset;
        
        if (match < reinterpret_cast<uint8_t*>(output.data())) {
            return std::unexpected(make_error_code(error_code::decompression_failed));
        }
        
        // Decode match length
        size_t match_length = token & ML_MASK;
        if (match_length == ML_MASK) {
            uint8_t s;
            do {
                if (ip >= iend) {
                    return std::unexpected(make_error_code(error_code::decompression_failed));
                }
                s = *ip++;
                match_length += s;
            } while (s == 255);
        }
        match_length += MIN_MATCH;
        
        // Copy match
        cpy = op + match_length;
        if (cpy > oend) {
            return std::unexpected(make_error_code(error_code::invalid_buffer_size));
        }
        
        // Handle overlapping copies
        if (offset < 8) {
            // Slow path for overlapping data
            const uint8_t* match_end = match + match_length;
            while (match < match_end) {
                *op++ = *match++;
            }
        } else {
            // Fast path
            wild_copy(op, match, cpy);
            op = cpy;
        }
    }
    
    return op - reinterpret_cast<uint8_t*>(output.data());
}

// ────────────────────────────────────────────────────────────────────────────
// LZ4 High Compression
// ────────────────────────────────────────────────────────────────────────────

// Helper function to emit a sequence (literals + match)
static bool emit_sequence(
    std::span<const std::byte> input,
    std::span<std::byte> output,
    size_t literal_start,
    size_t literal_len,
    size_t match_dist,
    size_t match_len,
    size_t& dst_pos
) noexcept {
    // Check space for token
    if (dst_pos >= output.size()) return false;
    
    // Encode token
    uint8_t token = 0;
    
    // Literal length in token (4 bits)
    if (literal_len < 15) {
        token = static_cast<uint8_t>(literal_len << 4);
    } else {
        token = 0xF0;
    }
    
    // Match length in token (4 bits)
    size_t encoded_match_len = match_len - 4;  // LZ4 encodes match_len - 4
    if (encoded_match_len < 15) {
        token |= static_cast<uint8_t>(encoded_match_len);
    } else {
        token |= 0x0F;
    }
    
    output[dst_pos++] = static_cast<std::byte>(token);
    
    // Encode extended literal length if needed
    if (literal_len >= 15) {
        size_t len = literal_len - 15;
        while (len >= 255 && dst_pos < output.size()) {
            output[dst_pos++] = static_cast<std::byte>(255);
            len -= 255;
        }
        if (dst_pos >= output.size()) return false;
        output[dst_pos++] = static_cast<std::byte>(len);
    }
    
    // Copy literals
    if (dst_pos + literal_len > output.size()) return false;
    std::memcpy(&output[dst_pos], &input[literal_start], literal_len);
    dst_pos += literal_len;
    
    // Encode match offset (little-endian)
    if (dst_pos + 2 > output.size()) return false;
    output[dst_pos] = static_cast<std::byte>(match_dist & 0xFF);
    output[dst_pos + 1] = static_cast<std::byte>((match_dist >> 8) & 0xFF);
    dst_pos += 2;
    
    // Encode extended match length if needed
    if (encoded_match_len >= 15) {
        size_t len = encoded_match_len - 15;
        while (len >= 255 && dst_pos < output.size()) {
            output[dst_pos++] = static_cast<std::byte>(255);
            len -= 255;
        }
        if (dst_pos >= output.size()) return false;
        output[dst_pos++] = static_cast<std::byte>(len);
    }
    
    return true;
}

// Helper function to emit final literals
static bool emit_final_literals(
    std::span<const std::byte> input,
    std::span<std::byte> output,
    size_t literal_start,
    size_t end_pos,
    size_t& dst_pos
) noexcept {
    size_t literal_len = end_pos - literal_start;
    if (literal_len == 0) return true;
    
    // Check space for token
    if (dst_pos >= output.size()) return false;
    
    // Encode token (only literals, no match)
    uint8_t token = 0;
    if (literal_len < 15) {
        token = static_cast<uint8_t>(literal_len << 4);
    } else {
        token = 0xF0;
    }
    
    output[dst_pos++] = static_cast<std::byte>(token);
    
    // Encode extended literal length if needed
    if (literal_len >= 15) {
        size_t len = literal_len - 15;
        while (len >= 255 && dst_pos < output.size()) {
            output[dst_pos++] = static_cast<std::byte>(255);
            len -= 255;
        }
        if (dst_pos >= output.size()) return false;
        output[dst_pos++] = static_cast<std::byte>(len);
    }
    
    // Copy literals
    if (dst_pos + literal_len > output.size()) return false;
    std::memcpy(&output[dst_pos], &input[literal_start], literal_len);
    dst_pos += literal_len;
    
    return true;
}

result<size_t> lz4::compress_hc(
    std::span<const std::byte> input,
    std::span<std::byte> output
) noexcept {
    // High compression variant with chain-based match finding
    if (input.empty()) return 0;
    if (output.size() < 1) return std::unexpected(error_code::buffer_too_small);
    
    const size_t min_match = 4;
    const size_t max_distance = 65535;
    const size_t chain_length = 256;  // Max chain depth for searching
    
    // Hash table with chains for better match finding
    struct chain_entry {
        uint32_t pos;
        uint32_t next;
    };
    
    std::vector<uint32_t> hash_table(1 << 16, 0xFFFFFFFF);
    std::vector<chain_entry> chains;
    chains.reserve(input.size() / 4);  // Estimate
    
    size_t src_pos = 0;
    size_t dst_pos = 0;
    size_t literal_start = 0;
    
    auto hash4 = [](const std::byte* p) -> uint32_t {
        uint32_t v;
        std::memcpy(&v, p, 4);
        return (v * 0x9E3779B1) >> 16;  // Golden ratio hash
    };
    
    // Build hash chains
    while (src_pos + min_match <= input.size()) {
        if (src_pos + 12 > input.size()) break;
        
        uint32_t hash = hash4(&input[src_pos]);
        uint32_t old_head = hash_table[hash];
        hash_table[hash] = chains.size();
        chains.push_back({static_cast<uint32_t>(src_pos), old_head});
        
        // Find best match in chain
        size_t best_match_len = 0;
        size_t best_match_dist = 0;
        
        uint32_t chain_pos = old_head;
        size_t chain_depth = 0;
        
        while (chain_pos != 0xFFFFFFFF && chain_depth < chain_length) {
            if (chain_pos >= chains.size()) break;
            
            size_t match_pos = chains[chain_pos].pos;
            if (src_pos - match_pos > max_distance) break;
            
            // Check match length
            size_t match_len = 0;
            while (match_len < 255 && 
                   src_pos + match_len < input.size() &&
                   input[match_pos + match_len] == input[src_pos + match_len]) {
                match_len++;
            }
            
            if (match_len >= min_match && match_len > best_match_len) {
                best_match_len = match_len;
                best_match_dist = src_pos - match_pos;
            }
            
            chain_pos = chains[chain_pos].next;
            chain_depth++;
        }
        
        // Emit literals or match
        if (best_match_len >= min_match) {
            // Emit literals before match
            size_t literal_len = src_pos - literal_start;
            if (!emit_sequence(input, output, literal_start, literal_len,
                             best_match_dist, best_match_len, dst_pos)) {
                return std::unexpected(error_code::buffer_too_small);
            }
            
            src_pos += best_match_len;
            literal_start = src_pos;
        } else {
            src_pos++;
        }
    }
    
    // Emit final literals
    if (!emit_final_literals(input, output, literal_start, input.size(), dst_pos)) {
        return std::unexpected(error_code::buffer_too_small);
    }
    
    return dst_pos;
}

// ────────────────────────────────────────────────────────────────────────────
// LZ4 Frame Format
// ────────────────────────────────────────────────────────────────────────────

result<std::vector<std::byte>> lz4_frame::compress_frame(
    std::span<const std::byte> input,
    const frame_descriptor& desc
) noexcept {
    // Simple frame format implementation
    std::vector<std::byte> output;
    output.reserve(input.size() + 32);  // Reserve with some overhead
    
    // Write magic number
    uint32_t magic = MAGIC;
    output.insert(output.end(), 
        reinterpret_cast<std::byte*>(&magic),
        reinterpret_cast<std::byte*>(&magic) + 4);
    
    // Write frame descriptor (simplified)
    output.push_back(std::byte{0x60});  // Version 01, no checksum, independent blocks
    output.push_back(std::byte{0x00});  // Block max size: 64KB
    
    // Compress in blocks
    lz4 compressor;
    const size_t block_size = desc.max_block_size;
    size_t offset = 0;
    
    while (offset < input.size()) {
        size_t chunk_size = std::min(block_size, input.size() - offset);
        auto chunk = input.subspan(offset, chunk_size);
        
        // Compress block
        std::vector<std::byte> compressed(compressor.max_compressed_size(chunk_size));
        auto result = compressor.compress(chunk, compressed);
        if (!result) {
            return std::unexpected(result.error());
        }
        
        // Write block size
        uint32_t block_size_val = static_cast<uint32_t>(*result);
        output.insert(output.end(),
            reinterpret_cast<std::byte*>(&block_size_val),
            reinterpret_cast<std::byte*>(&block_size_val) + 4);
        
        // Write compressed data
        output.insert(output.end(), compressed.begin(), compressed.begin() + *result);
        
        offset += chunk_size;
    }
    
    // Write end marker
    uint32_t end_marker = 0;
    output.insert(output.end(),
        reinterpret_cast<std::byte*>(&end_marker),
        reinterpret_cast<std::byte*>(&end_marker) + 4);
    
    return output;
}

result<std::vector<std::byte>> lz4_frame::decompress_frame(
    std::span<const std::byte> input
) noexcept {
    if (input.size() < 7) {
        return std::unexpected(make_error_code(error_code::decompression_failed));
    }
    
    // Check magic number
    uint32_t magic;
    std::memcpy(&magic, input.data(), 4);
    if (magic != MAGIC) {
        return std::unexpected(make_error_code(error_code::decompression_failed));
    }
    
    // Skip frame descriptor (simplified)
    size_t offset = 7;
    
    std::vector<std::byte> output;
    lz4 decompressor;
    
    // Decompress blocks
    while (offset + 4 <= input.size()) {
        // Read block size
        uint32_t block_size;
        std::memcpy(&block_size, input.data() + offset, 4);
        offset += 4;
        
        // Check for end marker
        if (block_size == 0) break;
        
        // Decompress block
        if (offset + block_size > input.size()) {
            return std::unexpected(make_error_code(error_code::decompression_failed));
        }
        
        auto compressed = input.subspan(offset, block_size);
        
        // Estimate decompressed size (use 4x for safety)
        std::vector<std::byte> decompressed(block_size * 4);
        auto result = decompressor.decompress(compressed, decompressed);
        if (!result) {
            return std::unexpected(result.error());
        }
        
        // Append to output
        output.insert(output.end(), decompressed.begin(), decompressed.begin() + *result);
        
        offset += block_size;
    }
    
    return output;
}

} // namespace psyfer::compression