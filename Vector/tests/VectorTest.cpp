
#include "gtest/gtest.h"
#include "vector.cpp"

template <typename T>
class MyFixture : public testing::Test {};
using MyTypes = ::testing::Types<int, double, char, int*, double*, char*,
  vector<int>, vector<char>, vector <double>, int**, double**, char**>;
TYPED_TEST_SUITE(MyFixture, MyTypes);

TYPED_TEST(MyFixture, Vector) {

  TypeParam a, b;
  vector<TypeParam> vec;

  vec.push_back(a);
  EXPECT_EQ(vec.size(), 1);
  EXPECT_EQ(a == vec[0], true);

  vec.push_back(b);
  EXPECT_EQ(vec.size(), 2);
  EXPECT_EQ(b == vec[1], true);

  vec.pop_back();
  EXPECT_EQ(vec.size(), 1);

  vec.resize(5);
  EXPECT_EQ(vec.size(), 5);

}

TYPED_TEST(MyFixture, VectorOfVectors) {

  vector<vector<TypeParam>> vv;
  vector<TypeParam> v1, v2;
  TypeParam a, b, c, d, e;

  v1.push_back(a);
  v1.push_back(b);
  v1.push_back(c);

  v2.push_back(d);
  v2.push_back(e);

  vv.push_back(v1);
  vv.push_back(v2);

  EXPECT_EQ(vv.size(), 2);
  EXPECT_EQ(v1 == vv[0], true);
  EXPECT_EQ(v2 == vv[1], true);

  vv.pop_back();
  EXPECT_EQ(vv.size(), 1);
  EXPECT_EQ(v1 == vv[0], true);

  vv.resize(5);
  EXPECT_EQ(vv.size(), 5);

}
