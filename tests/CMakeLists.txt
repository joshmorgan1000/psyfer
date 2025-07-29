# Function to add a test executable with common settings
function(add_psyfer_test test_name)
    add_executable(${test_name} ${test_name}.cpp)
    target_link_libraries(${test_name} PRIVATE psyfer)
    target_compile_features(${test_name} PRIVATE cxx_std_23)
    # Pass through HAVE_CRYPTOKIT if defined
    if(TARGET psyfer_cryptokit)
        target_compile_definitions(${test_name} PRIVATE HAVE_CRYPTOKIT=1)
    endif()
    # Add sanitizers for debugging
    # Disabled for now due to Swift linking issues
    # if(APPLE)
    #     target_compile_options(${test_name} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    #     target_link_options(${test_name} PRIVATE -fsanitize=address)
    # endif()
    # Add include directories
    target_include_directories(${test_name} PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
    )
    # Enable testing
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# Add all pattern tests
add_psyfer_test(test_aes256)
add_psyfer_test(test_aes_cmac)
add_psyfer_test(test_chacha20)
add_psyfer_test(test_secure)
add_psyfer_test(test_secure_key)
add_psyfer_test(test_aes_hw)
add_psyfer_test(test_preprocessor)
add_psyfer_test(test_hash_performance)
add_psyfer_test(test_sha)
add_psyfer_test(test_hkdf)
add_psyfer_test(test_ed25519)
add_psyfer_test(test_lz4)
add_psyfer_test(test_x25519)
add_psyfer_test(test_xxhash3)
add_psyfer_test(test_xxhash3_distribution)
add_psyfer_test(test_xxhash3_32bit_distribution)
add_psyfer_test(test_xxhash3_24bit)
add_psyfer_test(test_fpc)
add_psyfer_test(test_fpc_debug)

# Add CryptoKit test only on Apple platforms
if(APPLE)
    add_psyfer_test(test_x25519_cryptokit)
    add_executable(test_cryptokit test_cryptokit.cpp)
    target_compile_features(test_cryptokit PRIVATE cxx_std_23)
endif()
