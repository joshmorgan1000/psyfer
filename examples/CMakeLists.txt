cmake_minimum_required(VERSION 3.20)

# Add example executables
add_executable(basic_encryption basic_encryption.cpp)
target_link_libraries(basic_encryption PRIVATE psyfer)
target_compile_features(basic_encryption PRIVATE cxx_std_23)

add_executable(password_encryption password_encryption.cpp)
target_link_libraries(password_encryption PRIVATE psyfer)
target_compile_features(password_encryption PRIVATE cxx_std_23)

add_executable(hashing_example hashing_example.cpp)
target_link_libraries(hashing_example PRIVATE psyfer)
target_compile_features(hashing_example PRIVATE cxx_std_23)

# Add more examples here as needed