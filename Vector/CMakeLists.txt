
cmake_minimum_required(VERSION 3.5)
project(Vector)

set(CMAKE_CXX_STANDARD 14)

include_directories(${PROJECT_SOURCE_DIR}/src)
add_subdirectory(tests)
add_subdirectory(libs/googletest)
