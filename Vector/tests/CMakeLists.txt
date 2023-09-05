
enable_testing()

add_executable(VectorTEST VectorTest.cpp)
target_link_libraries(VectorTEST
  gtest gtest_main gcov
)

add_test(mytest
    VectorTEST
)

SET(GCC_COVERAGE_COMPILE_FLAGS "-g -O0 -coverage -fprofile-arcs -ftest-coverage")
add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})
