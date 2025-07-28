cmake_minimum_required(VERSION 3.20)
project(psyfer VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_subdirectory(third_party/BLAKE3/c EXCLUDE_FROM_ALL)

add_library(psyfer
    STATIC
    src/psyfer.cpp
    src/logger/logger.cpp
)
target_include_directories(psyfer PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(psyfer PUBLIC
    blake3
)
target_include_directories(psyfer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(psyfer PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:
        $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
            -Wall -Wextra -Wpedantic -Werror
            $<$<CONFIG:Debug>:-O0 -g -DDEBUG>
            $<$<CONFIG:Release>:-O3 -DNDEBUG>
        >
        $<$<CXX_COMPILER_ID:MSVC>:
            /W4 /WX
            $<$<CONFIG:Debug>:/Od /Zi /DDEBUG>
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
install(TARGETS psyne_encrypt ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
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
# Print configuration summary
# ──────────────────────────────────────────────────────────────
message(STATUS "────────────────────────────────────────────────────")
message(STATUS "   _____  _______ __   __ _______ _______  ______")
message(STATUS "  |_____] |______   \\_/   |______ |______ |_____/")
message(STATUS "  |       ______|    |    |       |______ |    \\_")
message(STATUS "────────────────────────────────────────────────────")
message(STATUS "  Psyfer Encryption Library configured:")
message(STATUS "    Version: ${PROJECT_VERSION}")
message(STATUS "    C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "─────────────────────────────────────────────────────")
