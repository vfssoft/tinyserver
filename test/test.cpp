
#include <gtest/gtest.h>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  //::testing::GTEST_FLAG(filter) = "*SSLConnectDisconnect1sTest*";
  return RUN_ALL_TESTS();
}