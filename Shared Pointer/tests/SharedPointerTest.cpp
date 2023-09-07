
#include "gtest/gtest.h"
#include "shared_ptr.cpp"
#include <vector>
#include <thread>

template <typename T>
class MyFixture : public testing::Test {};
using MyTypes = ::testing::Types<int, char, double, int*, double*, char*>;
TYPED_TEST_SUITE(MyFixture, MyTypes);

TYPED_TEST(MyFixture, UseCount) {

  shared_ptr<TypeParam> ptr1(new TypeParam);
  EXPECT_EQ(ptr1.use_count(), 1);
  {
    shared_ptr<TypeParam> ptr2(new TypeParam);
    ptr2 = ptr1;
    EXPECT_EQ(ptr1.use_count(), 2);
    {
      shared_ptr<TypeParam> ptr3(ptr2);
      EXPECT_EQ(ptr1.use_count(), 3);
    }
    EXPECT_EQ(ptr1.use_count(), 2);
  }
  EXPECT_EQ(ptr1.use_count(), 1);
  
}

TEST(RegularTest, ChangeValue) {

  int* a = new int;
  *a = 5;
  shared_ptr<int> ptr1(a);
  shared_ptr<int> ptr2 = ptr1, ptr3(new int);
  ptr3 = ptr2;

  EXPECT_EQ(*(ptr1.get()), 5);
  EXPECT_EQ(*(ptr2.get()), 5);
  EXPECT_EQ(*(ptr3.get()), 5);

  *ptr1 = 9;

  EXPECT_EQ(*a, 9);
  EXPECT_EQ(*(ptr1.get()), 9);
  EXPECT_EQ(*(ptr2.get()), 9);
  EXPECT_EQ(*(ptr3.get()), 9);

}

TEST(RegularTest, Test_Type) {

  Test_Type* test = new Test_Type;

  {
    shared_ptr<Test_Type> ptr(test);
    EXPECT_EQ(ptr.use_count(), 1);
  }

  EXPECT_EQ(Test_Type::deleted, true);

}

TEST(RegularTest, ThreadsTest) {

  shared_ptr<int> ptr(new int);

  auto func = [&ptr] () {
    shared_ptr<int> p1(ptr);
    {
      shared_ptr<int> p2(ptr);
    }
  };

  std::vector<std::thread> pool;
  for(int i = 0; i < 1000; i++) {
    std::thread th(func);
    pool.push_back(std::move(th));
  } 
  for(int i = 0; i < 1000; i++) {
    (pool[i]).join();
  } 

  EXPECT_EQ(ptr.use_count(), 1);

}
