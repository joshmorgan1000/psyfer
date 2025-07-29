# FindSodium.cmake
# Finds the libsodium cryptography library
#
# This will define the following variables:
#  Sodium_FOUND - True if the system has libsodium
#  Sodium_INCLUDE_DIRS - The libsodium include directories
#  Sodium_LIBRARIES - The libraries needed to use libsodium

find_path(Sodium_INCLUDE_DIR
    NAMES sodium.h
    PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium/src/libsodium/include
        /usr/local/include
        /usr/include
)

find_library(Sodium_LIBRARY
    NAMES sodium
    PATHS
        ${CMAKE_CURRENT_BINARY_DIR}/third_party/libsodium
        /usr/local/lib
        /usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium DEFAULT_MSG
    Sodium_LIBRARY Sodium_INCLUDE_DIR)

if(Sodium_FOUND)
    set(Sodium_LIBRARIES ${Sodium_LIBRARY})
    set(Sodium_INCLUDE_DIRS ${Sodium_INCLUDE_DIR})
endif()

mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)