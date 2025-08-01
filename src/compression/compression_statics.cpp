/**
 * @file compression_statics.cpp
 * @brief Static member definitions for compression classes
 */

#include <psyfer.hpp>

namespace psyfer {

// Define the static member for CompressionAlgorithm
std::shared_ptr<goldenhash::GoldenHash> CompressionAlgorithm::hash = std::make_shared<goldenhash::GoldenHash>(1827);

} // namespace psyfer