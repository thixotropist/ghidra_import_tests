#include <gtest/gtest.h>
#include <glog/logging.h>
#include "pcodeTests.h"
namespace {

TEST(VectorMove, vmv_s_x) {
    // exercise vmv.s.x and vmv.x.s to move a scalar into and out of the first element of a
    // vector register
    EXPECT_TRUE(test_integer_scalar_vector_move()) << "Integer Scalar Vector Moves into and out of Vector register work";
}

TEST(VectorMove, test_vmv1r_v) {
    EXPECT_TRUE(test_vmv1r_v()) << "vector to vector copy";
}

TEST(VectorMove, test_vid_v) {
    EXPECT_TRUE(test_vid_v()) << "vector index, store to memory";
}

TEST(FloatConversion, fmv_x_w) {
    EXPECT_TRUE(test_fmv_x_w()) << "Float to scalar move does not convert";
}

TEST(FloatConversion, fmv_w_x) {
    EXPECT_TRUE(test_fmv_w_x()) << "Scalar to float move does not convert";
}



}  // namespace

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    google::InitGoogleLogging("pcodeTests");
    int results = RUN_ALL_TESTS();
    google::ShutdownGoogleLogging();
    return results;
}
