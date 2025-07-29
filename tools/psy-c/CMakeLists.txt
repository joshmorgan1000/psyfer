cmake_minimum_required(VERSION 3.20)
project(psy-c VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files
set(PSY_C_SOURCES
    src/main.cpp
    src/lexer.cpp
    src/parser.cpp
    src/ast.cpp
    src/code_generator.cpp
    src/type_system.cpp
    src/schema.cpp
)

# Create the executable
add_executable(psy-c ${PSY_C_SOURCES})

# Include directories
target_include_directories(psy-c PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include  # For psyfer headers
)

# Compile options
target_compile_options(psy-c PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
        -Wall -Wextra -Wpedantic
        $<$<CONFIG:Debug>:-g -O0>
        $<$<CONFIG:Release>:-O3>
    >
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4
        $<$<CONFIG:Debug>:/Od /Zi>
        $<$<CONFIG:Release>:/O2>
    >
)

# Install rules
install(TARGETS psy-c
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Test executable
add_executable(test_psy test_psy.cpp)
target_link_libraries(test_psy PRIVATE psyfer)
target_include_directories(test_psy PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

# Full pipeline test
add_executable(test_full_pipeline test_full_pipeline.cpp)
target_link_libraries(test_full_pipeline PRIVATE psyfer)
target_include_directories(test_full_pipeline PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

# Simple compression test
add_executable(test_simple_compression test_simple_compression.cpp)
target_link_libraries(test_simple_compression PRIVATE psyfer)
target_include_directories(test_simple_compression PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)