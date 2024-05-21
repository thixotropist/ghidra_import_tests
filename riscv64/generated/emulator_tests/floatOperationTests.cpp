#include <gtest/gtest.h>
#include <glog/logging.h>
#include <limits>

extern "C"
{
#include "floatOperations.h"
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

    /**
     * @brief verify our testharness helper functions first
     * 
     */
    TEST(FP, testharness)
    {
        float xmax = 65504.0;
        float xmin = -65504.0;

        // 1.0 encoded as _fp16 is 0x3c00
        short fp16_1 = fp16_as_short(short_as_fp16(0x3c00));
        LOG(INFO) << "_fp16(1.0) = 0x" << std::hex << std::setw(4) << \
            fp16_1;
        EXPECT_EQ(fp16_1, 0x3c00);

        // 1.0 as _fp16 is held in registers "NaN-boxed", with leading ones
        int fp16_1_in_register = fp16_as_int(short_as_fp16(0x3c00));
        LOG(INFO) << "_fp(1.0) in register = 0x" << std::hex << std::setw(8) << \
            fp16_1_in_register;
        EXPECT_EQ(fp16_1_in_register, 0xffff3c00);

        // Test max and min _fp16
        LOG(INFO) << "_fp(65504.0) = 0x" << std::hex << std::setw(4) << \
            fp16_as_short(fcvt_h_s(&xmax));
        LOG(INFO) << "_fp(-65504.0) = 0x" << std::hex << std::setw(4) << \
            fp16_as_short(fcvt_h_s(&xmin));
    }
    TEST(FP, loadstore)
    {
        float x = 1.0;
        float result = flw(&x);
        EXPECT_EQ(result, x) << "flw failure to load";
    }
/**
 * @brief Test conversion between ints/shorts and floats/doubles
 * 
 */
    TEST(FP, fcvt)
    {
        float x = 1.0;
        double xd = 1.0;

        double xdNan = std::numeric_limits<double>::quiet_NaN();
        int i = 1;
        unsigned int iu = 1;
        unsigned int iumax = 0xffffffff;
        double UINT_MAX_AS_DOUBLE = (double)0xffffffff;

        EXPECT_EQ(1, fcvt_w_s(&x)) << \
            "fcvt.w.s failure converting float to int32";

        EXPECT_EQ(1, fcvt_wu_s(&x)) << \
            "fcvt.wu.s failure converting float to uint32";

        EXPECT_EQ(1, fcvt_w_d(&xd)) << \
            "fcvt.w.d failure converting double to int32";

        EXPECT_EQ(1, fcvt_wu_d(&xd)) << \
            "fcvt.wu.d failure converting double to uint32";
        
        EXPECT_NEAR(1.0, fcvt_s_w(&i), 1.0e-5) << \
            "fcvt.s.w failure converting int32 to float";

        EXPECT_NEAR(1.0, fcvt_s_wu(&iu), 1.0e-5) << \
            "fcvt.s.wu failure converting uint32 to float";
        
        EXPECT_NEAR(UINT_MAX_AS_DOUBLE, fcvt_s_wu(&iumax), 1.0) << \
            "fcvt.s.wu failure converting large unsigned int to float";

        EXPECT_NEAR(1.0, fcvt_s_d(&xd), 1.0e-5) << \
            "fcvt.s.d failure converting double to float";

        // Convering NaN should throw a hardware exception
        GTEST_FLAG_SET(death_test_style, "threadsafe");
        EXPECT_DEATH(fcvt_s_d(&xdNan), "") << \
            "fcvt.s.d did not throw hardware exception on NaN conversion";
        GTEST_FLAG_SET(death_test_style, "fast");

        EXPECT_NEAR(1.0e0, fcvt_d_s(&x), 1.0e-10) << \
            "fcvt.d.s failure converting float to double";

        EXPECT_NEAR(1.0e0, fcvt_d_w(&i), 1.0e-10) << \
            "fcvt.d.w failure converting int32 to double";

        EXPECT_NEAR(1.0e0, fcvt_d_wu(&iu), 1.0e-10) << \
            "fcvt.d.wu failure converting uint32 to double";

        EXPECT_NEAR(UINT_MAX_AS_DOUBLE, fcvt_d_wu(&iumax), 1.0) << \
            "fcvt.d.wu failure converting large unsigned int to double";
    }
    /**
     * @brief The fmv instructions copy raw bits between integer and FP
     * registers without conversion.
     * 
     */
    TEST(FP, fmv)
    {
        float x = 1.0;
        int x_as_int = 0x3f800000;

        LOG(INFO) << std::hex << fmv_x_w(&x);
        EXPECT_EQ(x_as_int, fmv_x_w(&x)) << "fmv.x.w failure";

        LOG(INFO) << fmv_w_x(&x_as_int);
        EXPECT_NEAR(1.0, fmv_w_x(&x_as_int), 1.0e-5) << "fmv.w.x failure";
        
    }
    /**
     * @brief Half precision floating point operations
     * @details These follow _fp16 IEEE standards, not Google BF16 floats
     * 
     */
    TEST(FP, fp16)
    {
        float xmax = 65504.0;
        float xmin = -65504.0;
        _fp16 result_16;
        float result_32;
        double result_64;
        float source = 1.0;
        _fp16 xh = short_as_fp16(0x3c00);

        LOG(INFO) << "1.0 (as float) == 0x" << std::hex << std::setw(8) << fp32_as_int(source);
        LOG(INFO) << "1.0 (as _fp16) == 0x" << std::hex << std::setw(4) << fp16_as_short(source);

        result_16 = fcvt_h_s(&source);
        LOG(INFO) << "fcvt_h_s(1.0) = " << std::hex << fp16_as_short(result_16);
        EXPECT_EQ(fp16_as_short(result_16), 0x3c00) << "fcvt_h_s failure";

        result_16 = fcvt_h_s(&xmax);
        LOG(INFO) << "fcvt_h_s(65504.0) = " << std::hex << fp16_as_short(result_16);
        EXPECT_EQ(fp16_as_short(result_16), 0x7bff) << "fcvt_h_s failure";

        result_16 = fcvt_h_s(&xmin);
        LOG(INFO) << "fcvt_h_s(-65504.0) = " << std::hex << fp16_as_short(result_16);
        EXPECT_EQ(fp16_as_short(result_16) & 0xffff, 0xfbff) << "fcvt_h_s failure";

        result_32 = fcvt_s_h(&xh);
        LOG(INFO) << "fcvt_s_h(0x3c00) = " << result_32;
        EXPECT_NEAR(result_32, 1.0e0, 1.0e-5) << "fcvt_s_h failure";

        result_64 = fcvt_d_h(&xh);
        LOG(INFO) << std::hex << fp16_as_short(result_64);
        EXPECT_NEAR(result_64, 1.0e0, 1.0e-5) << "fcvt_d_h failure";
    }
} // namespace

/**
 * @brief Exercise selected floating point operations to verify qemu emulation
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    // loglevels: INFO = 0, WARNING=1, ERROR=2, FATAL=3
    FLAGS_minloglevel = 1;
    GTEST_FLAG_SET(death_test_style, "fast");
    return RUN_ALL_TESTS();
}
