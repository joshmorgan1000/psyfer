cmake_minimum_required(VERSION 3.20)

# Function to add a psy-c test executable with common settings
function(add_psy_c_test test_name)
    add_executable(${test_name} ${test_name}.cpp)
    
    # Link against psyfer for utilities  
    target_link_libraries(${test_name} PRIVATE psyfer)
    
    # Set C++ standard
    target_compile_features(${test_name} PRIVATE cxx_std_23)
    
    # Include directories
    target_include_directories(${test_name} PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_SOURCE_DIR}/include
    )
    
    # Set runtime output directory to project root/build/psy-c/tests
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/psy-c/tests"
    )
    
    # Add compile options
    target_compile_options(${test_name} PRIVATE
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
    
    # Enable testing
    add_test(NAME ${test_name} 
        COMMAND ${test_name}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/psy-c/tests
    )
endfunction()

# Add psy-c specific tests here
# TODO: Fix build system to create psy-c as libraries instead of single executable
# add_psy_c_test(test_psy_compiler)