
enable_testing()

add_executable(SharedPointerTEST SharedPointerTest.cpp)
target_link_libraries(SharedPointerTEST
  gtest gtest_main gcov
)

add_test(mytest
  SharedPointerTEST
)

SET(GCC_COVERAGE_COMPILE_FLAGS "-g -O0 -coverage -fprofile-arcs -ftest-coverage")
add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})
