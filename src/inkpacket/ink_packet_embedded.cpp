/**
 * @file ink_packet_embedded.cpp
 * @brief Static storage definitions for embedded application size
 * 
 * This file creates the storage that will be patched post-compilation
 * with the actual size of the application binary.
 */

#include "../include/ink_packet.hpp"

namespace psyne::ink {

// Initialize with placeholder pattern - will be patched post-build
alignas(8) volatile uint64_t InkPacketEmbeddedSize::app_size = 0x5245484345414C50ULL; // "PLACEHER" in little endian

// Guard values to detect buffer overflows
namespace {
    alignas(4) volatile uint32_t guard_before = InkPacketEmbeddedSize::GUARD_BEFORE;
    alignas(4) volatile uint32_t guard_after = InkPacketEmbeddedSize::GUARD_AFTER;
    
    // Prevent unused variable warnings by using them in a dummy function
    [[maybe_unused]] static bool dummy_guard_usage() {
        return guard_before != 0 && guard_after != 0;
    }
}

} // namespace psyne::ink