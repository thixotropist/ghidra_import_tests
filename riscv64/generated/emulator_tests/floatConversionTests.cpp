#include <gtest/gtest.h>
#include <glog/logging.h>

extern "C"
{
#include "floatConversions.h"
}

namespace
{

    class Test1 : public ::testing::Test
    {

    protected:
        void
        SetUp() final
        {
            google::InitGoogleLogging("unitTests");
            LOG(INFO) << "Logging System Initialized.";
        }
        void TearDown() final
        {
            LOG(INFO) << "Logging System Terminated.";
            google::ShutdownGoogleLogging();
        }
    };

    TEST(FP, fcvt)
    {
        float x = 1.0;
        double xd = 1.0;
        int i = 1;
        unsigned int iu = 1;
        unsigned int iumax = 0xffffffff;
        EXPECT_EQ(1, fcvt_w_s(&x)) << "fcvt.w.s emulation failure";
        EXPECT_EQ(1, fcvt_wu_s(&x)) << "fcvt.wu.s emulation failure";
        EXPECT_EQ(1, fcvt_w_d(&xd)) << "fcvt.w.d emulation failure";
        EXPECT_EQ(1, fcvt_wu_d(&xd)) << "fcvt.wu.d emulation failure";
        EXPECT_NEAR(1.0, fcvt_s_w(&i), 1.0e-5) << "fcvt.s.w failure";
        EXPECT_NEAR(1.0, fcvt_s_wu(&iu), 1.0e-5) << "fcvt.s.wu failure";
        EXPECT_NEAR(4294967295.0, fcvt_s_wu(&iumax), 1.0) << "fcvt.s.wu failure on large unsigned ints";
        EXPECT_NEAR(1.0e0, fcvt_s_d(&xd), 1.0e-5) << "fcvt.s.d failure";
        EXPECT_NEAR(1.0e0, fcvt_d_s(&x), 1.0e-10) << "fcvt.d.s failure";
        EXPECT_NEAR(1.0e0, fcvt_d_w(&i), 1.0e-10) << "fcvt.d.w failure";
        EXPECT_NEAR(1.0e0, fcvt_d_wu(&iu), 1.0e-10) << "fcvt.d.wu failure";
        EXPECT_NEAR(4294967295.0, fcvt_d_wu(&iumax), 1.0) << "fcvt.d.wu failure on large unsigned ints";
    }
    TEST(FP, fmv)
    {
        float x = 1.0;
        int x_as_int = 0x3f800000;
        //std::cout << std::hex << fmv_x_w(&x) << std::endl;
        EXPECT_EQ(x_as_int, fmv_x_w(&x)) << "fmv.x.w failure";
        EXPECT_NEAR(1.0, fmv_w_x(&x_as_int), 1.0e-5) << "fmv.w.x failure";
        //std::cout << fmv_w_x(&x_as_int) << std::endl;
    }
} // namespace

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
