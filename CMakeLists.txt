cmake_minimum_required(VERSION 3.20)
project(psyfer VERSION 1.0.0 LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include required modules
include(CheckCXXCompilerFlag)

# Platform-specific base flags (before any architecture detection)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Base flags without architecture-specific options (C++ only)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX>:-Wall>
        $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
        $<$<COMPILE_LANGUAGE:CXX>:-Wpedantic>
        $<$<COMPILE_LANGUAGE:CXX>:-Wno-unused-parameter>
        $<$<COMPILE_LANGUAGE:CXX>:-Wno-unused-variable>
        $<$<COMPILE_LANGUAGE:CXX>:-ffast-math>
        $<$<COMPILE_LANGUAGE:CXX>:-funroll-loops>
        $<$<COMPILE_LANGUAGE:CXX>:-ftree-vectorize>
    )
    # Release-specific flags
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-O3>)
        add_compile_definitions(NDEBUG)
    else()
        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-O0> $<$<COMPILE_LANGUAGE:CXX>:-g>)
        # Sanitizers for debug (not on Apple due to issues)
        if(NOT APPLE)
            add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fsanitize=address> $<$<COMPILE_LANGUAGE:CXX>:-fsanitize=undefined>)
            add_link_options(-fsanitize=address -fsanitize=undefined)
        endif()
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_compile_options(
        /W4
        /fp:fast
        /Oi  # Enable intrinsic functions
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2 /GL)  # Whole program optimization
        add_link_options(/LTCG)  # Link-time code generation
        add_compile_definitions(NDEBUG)
    else()
        add_compile_options(/Od /Zi)
    endif()
endif()

# Add goldenhash submodule
add_subdirectory(goldenhash)

add_library(psyfer
    STATIC
    src/logger/logger.cpp
    src/psyfer.cpp
    src/psyfer_context.cpp
    src/hash/sha.cpp
    src/hash/xxhash3.cpp
    src/mac/aes_cmac.cpp
    src/kdf/hkdf.cpp
    src/crypto/aes128.cpp
    src/crypto/aes256.cpp
    src/crypto/ghash_portable.cpp
    src/crypto/chacha20.cpp
    src/crypto/ed25519.cpp
    src/crypto/ed25519_ops.cpp
    src/crypto/x25519.cpp
    src/compression/lz4.cpp
    src/compression/fpc.cpp
    src/utils/secure.cpp
    src/utils/secure_key.cpp
)

# Detect processor architecture
if(NOT DEFINED CMAKE_SYSTEM_PROCESSOR OR CMAKE_SYSTEM_PROCESSOR STREQUAL "")
    execute_process(COMMAND uname -m OUTPUT_VARIABLE CMAKE_SYSTEM_PROCESSOR OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

message(STATUS "Detected processor: ${CMAKE_SYSTEM_PROCESSOR}")

# Platform-specific implementations
if(APPLE)
    message(STATUS "Building with CommonCrypto support (macOS/iOS)")
    target_sources(psyfer PRIVATE src/crypto/aes256_commoncrypto.cpp)
    
    # Check if we can compile Swift
    include(CheckLanguage)
    check_language(Swift)
    if(CMAKE_Swift_COMPILER)
        enable_language(Swift)
        set(CMAKE_Swift_LANGUAGE_VERSION 5)
        
        # Remove problematic flags from Swift
        string(REPLACE "-incremental" "" CMAKE_Swift_FLAGS_DEBUG "${CMAKE_Swift_FLAGS_DEBUG}")
        
        message(STATUS "Building with CryptoKit support for X25519 and Ed25519")
        
        # Create Swift static library first
        add_library(psyfer_cryptokit STATIC 
            src/crypto/x25519_cryptokit.swift
            src/crypto/ed25519_cryptokit.swift
        )
        
        # Swift compilation flags
        target_compile_options(psyfer_cryptokit PRIVATE
            -parse-as-library
            -emit-library
            -emit-module
            -module-name PsyferCryptoKit
            $<$<CONFIG:Debug>:-Onone -g>
            $<$<CONFIG:Release>:-O -whole-module-optimization>
        )
        
        # Swift module properties
        set_target_properties(psyfer_cryptokit PROPERTIES
            Swift_MODULE_NAME PsyferCryptoKit
            Swift_MODULE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/swift_modules
            POSITION_INDEPENDENT_CODE ON
        )
        
        # Link with CryptoKit framework
        target_link_libraries(psyfer_cryptokit PRIVATE "-framework CryptoKit")
        
        # Make psyfer depend on the Swift library
        target_link_libraries(psyfer PUBLIC psyfer_cryptokit)
        
        # Add compile definition to enable CryptoKit in C++
        target_compile_definitions(psyfer PRIVATE HAVE_CRYPTOKIT=1)
    else()
        message(STATUS "Swift compiler not found - X25519 and Ed25519 will use software implementation")
    endif()
    
    target_link_libraries(psyfer PUBLIC "-framework Security")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64)")
    message(STATUS "Building with x86_64 AES-NI support")
    target_sources(psyfer PRIVATE 
        src/crypto/aes256_ni.cpp
        src/crypto/aes128_ni.cpp
    )
    target_compile_options(psyfer PRIVATE 
        $<$<COMPILE_LANG_AND_ID:CXX,Clang,AppleClang,GNU>:-maes -msse4.1 -mpclmul>
    )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(arm64|aarch64)")
    message(STATUS "Building with ARM64 crypto extensions support")
    target_sources(psyfer PRIVATE src/crypto/aes_arm64.cpp)
endif()
target_include_directories(psyfer PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_include_directories(psyfer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Find and link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(psyfer PUBLIC OpenSSL::Crypto)
target_compile_definitions(psyfer PRIVATE HAVE_OPENSSL=1)

# Link goldenhash
target_link_libraries(psyfer PUBLIC goldenhash)
target_compile_options(psyfer PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:
        $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
            -Wall -Wextra -Wpedantic
            -march=native
            $<$<CONFIG:Debug>:-O0 -g>
            $<$<CONFIG:Release>:-O3 -DNDEBUG>
        >
        $<$<CXX_COMPILER_ID:MSVC>:
            /W4
            $<$<CONFIG:Debug>:/Od /Zi>
            $<$<CONFIG:Release>:/O2 /DNDEBUG>
        >
    >
)
if(ENABLE_ASAN)
    target_compile_options(psyfer PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-fsanitize=address>)
    target_link_options(psyfer PUBLIC -fsanitize=address)
endif()
if(ENABLE_TSAN)
    target_compile_options(psyfer PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-fsanitize=thread>)
    target_link_options(psyfer PUBLIC -fsanitize=thread)
endif()
if(GENERATE_ASSEMBLY AND CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET psyfer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Generating assembly output..."
        COMMAND objdump -d $<TARGET_FILE:psyfer> > ${CMAKE_CURRENT_BINARY_DIR}/psyfer.s
        COMMENT "Generating assembly output file"
        VERBATIM
    )
endif()
include(GNUInstallDirs)
install(TARGETS psyfer ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install ink packet headers
#install(DIRECTORY ink_packet/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/psyfer-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/psyfer-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/psyfer
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/psyfer-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/psyfer-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/psyfer-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/psyfer
)
if(GENERATE_ASSEMBLY AND CMAKE_BUILD_TYPE STREQUAL "Release")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/psyfer.s
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        OPTIONAL
    )
endif()
# ──────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────
add_subdirectory(tests)

# ──────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────
add_subdirectory(tools/psy-c)

# ──────────────────────────────────────────────────────────────
# Examples
# ──────────────────────────────────────────────────────────────
option(BUILD_EXAMPLES "Build example programs" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ──────────────────────────────────────────────────────────────
# Print configuration summary
# ──────────────────────────────────────────────────────────────
message(STATUS "______________________________________________________")
message(STATUS "    _____  _______ __   __ _______ _______  ______")
message(STATUS "   |_____] |______   \\_/   |______ |______ |_____/")
message(STATUS "   |       ______|    |    |       |______ |    \\_")
message(STATUS "──────────────────────────────────────────────────────")
message(STATUS "  Psyfer Encryption Library configured:")
message(STATUS "    Version: ${PROJECT_VERSION}")
message(STATUS "    C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "─────────────────────────────────────────────────────")
