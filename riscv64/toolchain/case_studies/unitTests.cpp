#include <gtest/gtest.h>
#include <glog/logging.h>
#include "mocks.h"

void print_block(const block_q8_0* b){
    std::cout << "Testing returned: " << "\n";
    std::cout << "\tq0 = 0x" << std::hex << b[0].d << ", " << std::dec;
    for (int i = 0; i < 32; i++) {
        std::cout << static_cast<signed int>(b[0].qs[i]) << ", ";
    }
    std::cout << "\n";
}

static const float fp32_test_array[0x20] = {
    0.0, -1.0, 2.0, -3.0, 4.0, -5.0, 6.0, -7.0, 8.0,
    -9.0, 10.0, -11.0, 12.0, -13.0, 14.0, -15.0, 16.0, -17.0,
    18.0, -19.0, 20.0, -21.0, 22.0, -23.0, 24.0, -25.0, 26.0,
    -27.0, 28.0, -29.0, 30.0, -31.0};

static const block_q8_0 fp16_test_array = {0x33d0,
     0,  -4,    8,  -12,  16,  -20,  25,  -29,
    33, -37,   41,  -45,  49,  -53,  57,  -61,
    66, -70,   74,  -78,  82,  -86,  90,  -94,
    98, -102, 107, -111, 115, -119, 123, -127
    };

namespace {

class Q8Test : public ::testing::Test {
 protected:
  void
  SetUp() final {
    google::InitGoogleLogging("unitTests");
    LOG(INFO) << "Logging System Initialized.";
  }
  void TearDown() final {
    LOG(INFO) << "Logging System Terminated.";
    google::ShutdownGoogleLogging();
  }
};

TEST(FP16, convertFromFp32Reference) {

    block_q8_0 dest[1];
    quantize_row_q8_0_reference(fp32_test_array, dest, 32);
    EXPECT_EQ(dest[0].d, fp16_test_array.d) << "fp16 scale factor is correct";
    int comparison = std::memcmp(dest,&fp16_test_array, sizeof(fp16_test_array));
    EXPECT_EQ(comparison, 0) << "entire fp16 block is converted correctly";
}

TEST(FP16, convertFromFp32VectorIntrinsics) {

    block_q8_0 dest[1];
    quantize_row_q8_0(fp32_test_array, dest, 32);
    EXPECT_EQ(dest[0].d, fp16_test_array.d) << "fp16 scale factor is correct";
    int comparison = std::memcmp(dest,&fp16_test_array, sizeof(fp16_test_array));
    EXPECT_EQ(comparison, 0) << "entire fp16 block is converted correctly";
}
}  // namespace


/// @brief execute the test suite
/// @param argc 
/// @param argv 
/// @return 
int
main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
