cmake_minimum_required(VERSION 3.10)

# Set compiler to g++-13
set(CMAKE_CXX_COMPILER "/usr/bin/g++-13")

# Set project name and version
project(CS50FinalWork VERSION 0.1)

# Set C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set build type to debug
set(CMAKE_BUILD_TYPE Debug)

# Set compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")

# Find and link to libsodium library
find_library(LIBSODIUM sodium)
if(NOT LIBSODIUM)
    message(FATAL_ERROR "libsodium library not found")
endif()
add_executable(RunMe main.cpp)
target_link_libraries(RunMe PUBLIC ${LIBSODIUM})

# Install target
install(TARGETS RunMe DESTINATION bin)
