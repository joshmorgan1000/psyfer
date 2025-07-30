# Function to add a test executable with common settings
function(add_psyfer_test test_name)
    add_executable(${test_name} ${test_name}.cpp)
    target_link_libraries(${test_name} PRIVATE psyfer)
    target_compile_features(${test_name} PRIVATE cxx_std_23)
    # Pass through HAVE_CRYPTOKIT if defined
    if(TARGET psyfer_cryptokit)
        target_compile_definitions(${test_name} PRIVATE HAVE_CRYPTOKIT=1)
    endif()
    # Pass through HAVE_OPENSSL if defined
    get_target_property(PSYFER_DEFS psyfer COMPILE_DEFINITIONS)
    if(PSYFER_DEFS MATCHES "HAVE_OPENSSL")
        target_compile_definitions(${test_name} PRIVATE HAVE_OPENSSL=1)
    endif()
    # Add include directories
    target_include_directories(${test_name} PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
    )
    # Enable testing
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# Add all unit tests - simple functional verification only
add_psyfer_test(test_aes_comprehensive)
add_psyfer_test(test_chacha20_comprehensive)
add_psyfer_test(test_cmac_comprehensive)
add_psyfer_test(test_crypto_vectors)
add_psyfer_test(test_ed25519_comprehensive)
add_psyfer_test(test_hmac_comprehensive)
add_psyfer_test(test_sha_comprehensive)
add_psyfer_test(test_x25519_comprehensive)
add_psyfer_test(test_xxhash3_comprehensive)
add_psyfer_test(test_openssl_crypto)
