cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

install(DIRECTORY DESTINATION build)
file(MAKE_DIRECTORY build)
execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory build)

project(CS50FinalWork VERSION 0.1)
find_library(LIBSODIUM sodium)

add_executable(RunMe main.cpp)

target_link_libraries(RunMe PUBLIC ${LIBSODIUM})