
add_executable(VectorTEST VectorTest.cpp)
target_link_libraries(VectorTEST
  gtest gtest_main
)

add_test(tests
    VectorTEST
)
