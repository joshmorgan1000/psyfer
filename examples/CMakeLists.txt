cmake_minimum_required(VERSION 3.20)
project(psyfer_examples LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find the psyfer library
# When building as part of the main project, psyfer target is already available
# When building standalone, users would need to find_package(psyfer)
if(NOT TARGET psyfer)
    find_package(psyfer REQUIRED)
endif()

# Function to add an example executable
function(add_psyfer_example name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE psyfer)
    
    # Force C++ linker for examples
    set_target_properties(${name} PROPERTIES
        LINKER_LANGUAGE CXX
    )
    
    # Add compile options for examples
    target_compile_options(${name} PRIVATE
        $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
            -Wall -Wextra -Wpedantic
            $<$<CONFIG:Debug>:-O0 -g>
            $<$<CONFIG:Release>:-O3>
        >
        $<$<CXX_COMPILER_ID:MSVC>:
            /W4
            $<$<CONFIG:Debug>:/Od /Zi>
            $<$<CONFIG:Release>:/O2>
        >
    )
endfunction()

# Add example executables
add_psyfer_example(01_basic_encryption)
add_psyfer_example(02_hashing)
add_psyfer_example(03_compression)
add_psyfer_example(04_key_exchange)
add_psyfer_example(05_digital_signatures)
add_psyfer_example(06_secure_keys)
add_psyfer_example(07_authenticated_encryption)
add_psyfer_example(08_key_derivation)
add_psyfer_example(09_message_authentication)
add_psyfer_example(10_user_buffer_decrypt)
add_psyfer_example(11_compress_then_encrypt)
add_psyfer_example(12_psy_c_generated)
add_psyfer_example(13_complete_example)

# Create a custom target to build all examples
add_custom_target(examples
    DEPENDS 
        01_basic_encryption
        02_hashing
        03_compression
        04_key_exchange
        05_digital_signatures
        06_secure_keys
        07_authenticated_encryption
        08_key_derivation
        09_message_authentication
        10_user_buffer_decrypt
        11_compress_then_encrypt
        12_psy_c_generated
        13_complete_example
)

# Installation rules for examples (optional)
if(INSTALL_EXAMPLES)
    install(TARGETS 
        01_basic_encryption
        02_hashing
        03_compression
        04_key_exchange
        05_digital_signatures
        06_secure_keys
        07_authenticated_encryption
        08_key_derivation
        09_message_authentication
        10_user_buffer_decrypt
        11_compress_then_encrypt
        12_psy_c_generated
        13_complete_example
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/psyfer_examples
    )
    
    # Install source files as reference
    install(FILES
        01_basic_encryption.cpp
        02_hashing.cpp
        03_compression.cpp
        04_key_exchange.cpp
        05_digital_signatures.cpp
        06_secure_keys.cpp
        07_authenticated_encryption.cpp
        08_key_derivation.cpp
        09_message_authentication.cpp
        10_user_buffer_decrypt.cpp
        11_compress_then_encrypt.cpp
        12_psy_c_generated.cpp
        13_complete_example.cpp
        DESTINATION ${CMAKE_INSTALL_DATADIR}/psyfer/examples
    )
endif()