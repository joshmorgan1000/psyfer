#pragma once

#include <string>
#include <vector>
#include <span>
#include <memory>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>
#include <random>
#include <algorithm>
#include <goldenhash.hpp>

namespace psyfer {

enum Lexicon {
    Size,           // Size of hash table to reference
    Seed,           // Seed for hash table gneration
    ChangeBit,      // Indicates dynamic size and seed change. Could be anywhere from 0 to 511 (9 bits)
    NextTableHint,  // Indicates the anti-data. We expect these values to be something, but they aren't, and that means something.
    KeyRotation     // Indicates a key rotation. Not sure how this will work yet.
};

// Now as part of the key, 31 lexicon combinations can be generated
static constexpr uint8_t LEXICON_SIZE_MINIMUM_BITS = 6;
static constexpr uint8_t LEXICON_SEED_MINIMUM_BITS = 3;
static constexpr uint8_t LEXICON_CHANGE_BIT_MINIMUM_BITS = 1;
static constexpr uint8_t LEXICON_NEXT_TABLE_HINT_MINIMUM_BITS = 2;
static constexpr uint8_t LEXICON_KEY_ROTATION_MINIMUM_BITS = 0;
// Total minimum bits for lexicon: 12 bits.

static constexpr uint8_t LEXICON_SIZE_MAXIMUM_BITS = 20;
static constexpr uint8_t LEXICON_SEED_MAXIMUM_BITS = 13;
static constexpr uint8_t LEXICON_CHANGE_BIT_MAXIMUM_BITS = 9;
static constexpr uint8_t LEXICON_NEXT_TABLE_HINT_MAXIMUM_BITS = 16;
static constexpr uint8_t LEXICON_KEY_ROTATION_MAXIMUM_BITS = 6;
// At least 4 bits will always be noise

struct BitMaskMeta {
    int bit_position; // Position of the bit in the block
    BitOperation operation; // Operation to perform on the bit
};

struct FieldDesc {
    Lexicon type;
    std::vector<BitMaskMeta> bits; // Which bits from the block belong to this field. Order matters.
};

struct KeyDesc {
    std::array<FieldDesc, 5> fields; // 5 fields for now
    KeyDesc(size_t seed) {
        // Randomly assign bit sizes to each field
        std::mt19937_64 rng(seed);
        // totalBits = random from 12 to 48 for example
        size_t totalBits = std::uniform_int_distribution<size_t>(12, 48)(rng);
        std::vector<int> allBits(64);
        std::iota(allBits.begin(), allBits.end(), 0);
        std::shuffle(allBits.begin(), allBits.end(), rng);
        for (size_t i = 0; i < fields.size(); ++i) {
            FieldDesc field;
            field.type = static_cast<Lexicon>(i);
            size_t bitsCount = std::uniform_int_distribution<size_t>(1, totalBits / fields.size())(rng);
            for (size_t j = 0; j < bitsCount; ++j) {
                BitMaskMeta bitMeta;
                bitMeta.bit_position = allBits.back();
                allBits.pop_back();
                field.bits.push_back(bitMeta);
            }
            fields[i] = field;
        }
    }
};

/**
 * @brief Stores actual instructions for the current block
 */
struct MetaBlock {
    uint32_t size; // Size of the block
    uint16_t seed; // Seed for the hash table
    uint16_t change_bit; // Change bit for the hash table
    uint16_t next_table_hint; // Next table hint for the hash table
    uint8_t key_rotation; // Key rotation for the hash table
    MetaBlock* previous_block;
};

static inline uint64_t get_hash_value_for(
    uint64_t* input,
    uint32_t table_size,
    uint16_t seed
) noexcept {
    // TODO: Cache hash tables so they don't have to be preloaded every time... maybe?
    goldenhash::GoldenHash hash(table_size, seed);
    return hash.hash(reinterpret_cast<const uint8_t*>(input), sizeof(uint64_t));
}

class HashChain {
private:
    std::vector<KeyDesc> key_chain_;
public:

    HashChain(size_t seed = 0) {
        for (size_t i = 0; i < 31; ++i) {
            key_chain_.emplace_back(seed + i);
        }
    }

    MetaBlock unpack_block(
        size_t chain_index,
        const uint64_t* block,
        const std::vector<KeyDesc>& key_chain)
    {
        uint64_t local_copy = *block;
        const KeyDesc& key_desc = key_chain[chain_index];
        MetaBlock meta_block{};
        for (size_t i = 0; i < key_desc.fields.size(); ++i) {
            const FieldDesc& field = key_desc.fields[i];
            uint64_t field_value = 0;
            for (size_t j = 0; j < field.bits.size(); ++j) {
                int read_bit_position = field.bits[j].bit_position;
                if (local_copy & (1ULL << read_bit_position)) {
                    field_value |= (1ULL << j);
                }
            }
            switch (i) {
                case 0: meta_block.size = uint32_t(field_value); break;
                case 1: meta_block.seed = uint16_t(field_value); break;
                case 2: meta_block.change_bit = uint16_t(field_value); break;
                case 3: meta_block.next_table_hint = uint16_t(field_value); break;
                case 4: meta_block.key_rotation = uint8_t(field_value); break;
            }
        }
        return meta_block;
    }

    uint64_t pack_block(
        size_t chain_index,
        const MetaBlock& meta,
        const std::vector<KeyDesc>& key_chain)
    {
        uint64_t block = 0;
        const KeyDesc& key_desc = key_chain[chain_index];
        for (size_t i = 0; i < key_desc.fields.size(); ++i) {
            const FieldDesc& field = key_desc.fields[i];
            uint64_t field_value = 0;
            // Map MetaBlock field to field_value
            switch (i) {
                case 0: field_value = meta.size; break;
                case 1: field_value = meta.seed; break;
                case 2: field_value = meta.change_bit; break;
                case 3: field_value = meta.next_table_hint; break;
                case 4: field_value = meta.key_rotation; break;
            }
            // Set bits in block according to mapping
            for (size_t j = 0; j < field.bits.size(); ++j) {
                if (field_value & (1ULL << j)) {
                    block |= (1ULL << field.bits[j].bit_position);
                }
            }
        }
        return block;
    }

    void serialize_key(std::ostream& out, const KeyDesc& key) {
        for (const auto& field : key.fields) {
            out.put(static_cast<uint8_t>(field.type));
            uint8_t bitsize = field.bits.size();
            out.put(bitsize);
            for (const auto& bit : field.bits) {
                out.put(bit.bit_position);
                out.put(static_cast<uint8_t>(bit.operation));
            }
        }
    }
    KeyDesc deserialize_key(std::istream& in) {
        
    }
};

}