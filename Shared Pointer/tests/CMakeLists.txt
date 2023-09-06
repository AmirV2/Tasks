
enable_testing()

add_executable(SahredPointerTEST SahredPointerTest.cpp)
target_link_libraries(SahredPointerTEST
  gtest gtest_main gcov
)

add_test(mytest
  SahredPointerTEST
)

SET(GCC_COVERAGE_COMPILE_FLAGS "-g -O0 -coverage -fprofile-arcs -ftest-coverage")
add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})
