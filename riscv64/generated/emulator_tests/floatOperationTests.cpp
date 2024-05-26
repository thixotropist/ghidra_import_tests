#include <gtest/gtest.h>
#include <glog/logging.h>
#include <limits>
#include <cstdint>

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
     * @brief verify our test harness helper functions first
     * 
     */
    TEST(FP, testharness)
    {
        float xmax = 65504.0;
        float xmin = -65504.0;

        // 1.0 encoded as _fp16 is 0x3c00
        uint16_t fp16_1 = fp16_as_short(short_as_fp16(0x3c00));
        LOG(INFO) << "_fp16(1.0) = 0x" << std::hex << std::setw(4) <<
            fp16_1;
        EXPECT_EQ(fp16_1, 0x3c00);

        // 1.0 as _fp16 is held in registers "NaN-boxed", with leading ones
        int32_t fp16_1_in_register = fp16_as_int(short_as_fp16(0x3c00));
        LOG(INFO) << "_fp(1.0) in register = 0x" << std::hex << std::setw(8) <<
            fp16_1_in_register;
        EXPECT_EQ(fp16_1_in_register, 0xffff3c00);

        // Test max and min _fp16
        LOG(INFO) << "_fp(65504.0) = 0x" << std::hex << std::setw(4) <<
            fp16_as_short(fcvt_h_s(&xmax));
        LOG(INFO) << "_fp(-65504.0) = 0x" << std::hex << std::setw(4) <<
            fp16_as_short(fcvt_h_s(&xmin));
    }
    /**
     * @brief Control test with 32 bit floats
     */
    TEST(FP, loadstore)
    {
        float x = 1.0;
        float result = flw(&x);
        EXPECT_EQ(result, x) << "flw failure to load 32 bit floating point";
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

        int32_t i = 1;
        uint32_t iu = 1;
        uint32_t iumax = 0xffffffff;
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
        int32_t x_as_int = 0x3f800000;

        LOG(INFO) << std::hex << fmv_x_w(&x);
        EXPECT_EQ(x_as_int, fmv_x_w(&x)) << "fmv.x.w failure";

        LOG(INFO) << fmv_w_x(&x_as_int);
        EXPECT_NEAR(1.0, fmv_w_x(&x_as_int), 1.0e-5) << "fmv.w.x failure";
    }
    /**
     * @brief Half precision floating point operations
     * @details These follow _fp16 IEEE standards, not Google BF16 floats
     */
    TEST(FP, fp16)
    {
        float xmax = 65504.0;
        float xmin = -65504.0;
        int32_t i1 = 1;
        uint32_t iu1 = 1;
        _fp16 fp_result_16;
        float fp_result_32;
        double fp_result_64;
        int32_t int32_result;
        uint32_t uint32_result;
        int64_t int64_result;
        uint64_t uint64_result;

        float source = 1.0;
        _fp16 xh = short_as_fp16(0x3c00);

        LOG(INFO) << "1.0 (as float) == 0x" << std::hex << std::setw(8) << fp32_as_int(source);
        LOG(INFO) << "1.0 (as _fp16) == 0x" << std::hex << std::setw(4) << fp16_as_short(source);

        fp_result_16 = flh(&xh);
        LOG(INFO) << "flh(&hx) = " << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), 0x3c00) << "flh failure";

        fp_result_16 = fcvt_h_s(&source);
        LOG(INFO) << "fcvt_h_s(1.0) = " << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), 0x3c00) << "fcvt_h_s failure";

        fp_result_16 = fcvt_h_s(&xmax);
        LOG(INFO) << "fcvt_h_s(65504.0) = " << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), 0x7bff) << "fcvt_h_s failure";

        fp_result_16 = fcvt_h_s(&xmin);
        LOG(INFO) << "fcvt_h_s(-65504.0) = " << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16) & 0xffff, 0xfbff) << "fcvt_h_s failure";

        fp_result_32 = fcvt_s_h(&xh);
        LOG(INFO) << "fcvt_s_h(0x3c00) = " << fp_result_32;
        EXPECT_NEAR(fp_result_32, 1.0e0, 1.0e-5) << "fcvt_s_h failure";

        int32_result = fcvt_w_h(&xh);
        LOG(INFO) << "fcvt_w_h(0x3c00) = " << int32_result;
        EXPECT_EQ(int32_result, 1) << "fcvt_w_h failure";

        uint32_result = fcvt_wu_h(&xh);
        LOG(INFO) << "fcvt_wu_h(0x3c00) = " << uint32_result;
        EXPECT_EQ(uint32_result, 1) << "fcvt_wu_h failure";

        fp_result_16 = fcvt_h_w(&i1);
        LOG(INFO) << "fcvt_h_w(&1) = " << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16) & 0xffff, 0x3c00) << "fcvt_h_w failure";

        fp_result_16 = fcvt_h_wu(&iu1);
        LOG(INFO) << "fcvt_h_wu(&1) = " << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16) & 0xffff, 0x3c00) << "fcvt_h_wu failure";

        fp_result_64 = fcvt_d_h(&xh);
        LOG(INFO) << std::hex << fp16_as_short(fp_result_64);
        EXPECT_NEAR(fp_result_64, 1.0e0, 1.0e-5) << "fcvt_d_h failure";

        int64_result = fcvt_l_h(&xh);
        LOG(INFO) << "fcvt_l_h(0x3c00) = " << int64_result;
        EXPECT_EQ(int64_result, 1) << "fcvt_l_h failure";

        uint64_result = fcvt_lu_h(&xh);
        LOG(INFO) << "fcvt_lu_h(0x3c00) = " << uint64_result;
        EXPECT_EQ(uint64_result, 1) << "fcvt_lu_h failure";

        const float cf1_0 = 1.0;
        _fp16 x_1 = fcvt_h_s(&cf1_0);
        const float cf2_0 = 2.0;
        _fp16 x_2 = fcvt_h_s(&cf2_0);
        const float cfm1_0 = -1.0;
        _fp16 x_m1 = fcvt_h_s(&cfm1_0);
        const float cf3_0 = 3.0;
        _fp16 x_3 = fcvt_h_s(&cf3_0);
        const float cf4_0 = 4.0;
        _fp16 x_4 = fcvt_h_s(&cf4_0);

        // generate some half precision constants to test with
        LOG(INFO) << "1.0 (as _fp16) = 0x" << std::hex << fp16_as_short(fcvt_h_s(&cf1_0));
        LOG(INFO) << "2.0 (as _fp16) = 0x" << std::hex << fp16_as_short(fcvt_h_s(&cf2_0));
        LOG(INFO) << "3.0 (as _fp16) = 0x" << std::hex << fp16_as_short(fcvt_h_s(&cf3_0));
        LOG(INFO) << "4.0 (as _fp16) = 0x" << std::hex << fp16_as_short(fcvt_h_s(&cf4_0));
        LOG(INFO) << "-1.0 (as _fp16) = 0x" << std::hex << fp16_as_short(fcvt_h_s(&cfm1_0));

        fp_result_16 = fadd_h(&x_1, &x_2);
        LOG(INFO) << "fadd_h(1.0, 2.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_3)) << 
            "fadd_h(1.0, 2.0) failure";

        fp_result_16 = fsub_h(&x_1, &x_2);
        LOG(INFO) << "fsub_h(1.0, 2.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_m1)) << 
            "fsub_h(1.0, 2.0) failure";

        fp_result_16 = fmul_h(&x_m1, &x_m1);
        LOG(INFO) << "fmul_h(-1.0, -1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_1)) << 
            "fmul_h(-1.0, -1.0) failure";

        fp_result_16 = fdiv_h(&x_2, &x_2);
        LOG(INFO) << "fdiv_h(2.0, 2.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_1)) << 
            "fdiv_h(2.0, 2.0) failure";

        fp_result_16 = fmin_h(&x_m1, &x_2);
        LOG(INFO) << "fmin_h(-1.0, 2.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_m1)) << 
            "fmin_h(-1.0, 2.0) failure";

        fp_result_16 = fmax_h(&x_m1, &x_2);
        LOG(INFO) << "fmax_h(-1.0, 2.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_2)) << 
            "fmax_h(-1.0, 2.0) failure";

        fp_result_16 = fsqrt_h(&x_4);
        LOG(INFO) << "fsqrt_h(4.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_2)) << 
            "fsqrt_h(2.0) failure";

        fp_result_16 = fsgnj_h(&x_1, &x_m1);
        LOG(INFO) << "fsgnj_h(1.0, -1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_m1)) << 
            "fsgnj_h(1.0, -1.0) failure";

        fp_result_16 = fsgnjn_h(&x_1, &x_m1);
        LOG(INFO) << "fsgnjn_h(1.0, -1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_1)) << 
            "fsgnjn_h(1.0, -1.0) failure";

        fp_result_16 = fsgnjx_h(&x_m1, &x_m1);
        LOG(INFO) << "fsgnjnx_h(-1.0, -1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_1)) << 
            "fsgnjx_h(-1.0, -1.0) failure";

        fp_result_16 = fabs_h(&x_m1);
        LOG(INFO) << "fabs_h(-1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_1)) << 
            "fabs_h(-1.0) failure";

        fp_result_16 = fneg_h(&x_1);
        LOG(INFO) << "fneg_h(1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_m1)) << 
            "fneg_h(1.0) failure";

        int32_t float_class = fclass_h(&x_m1);
        LOG(INFO) << "fclass_h(-1.0) = 0x" << std::hex << float_class;
        EXPECT_EQ(float_class, 0x2) <<
            "fclass(-1.0) not identifying a negative normal float";

        int32_t compare_result = feq_h(&x_m1, &x_m1);
        LOG(INFO) << "feq_h(-1.0, -1.0) = 0x" << std::hex << compare_result;
        EXPECT_EQ(compare_result, 0x1) <<
            "feq_h(-1.0, -1.0) failure";

        compare_result = fle_h(&x_m1, &x_m1);
        LOG(INFO) << "fle_h(-1.0, -1.0) = 0x" << std::hex << compare_result;
        EXPECT_EQ(compare_result, 0x1) <<
            "fle_h(-1.0, -1.0) failure";

        compare_result = fgt_h(&x_m1, &x_m1);
        LOG(INFO) << "fgt_h(-1.0, -1.0) = 0x" << std::hex << compare_result;
        EXPECT_EQ(compare_result, 0x0) <<
            "fgt_h(-1.0, -1.0) failure";

        fp_result_16 = fmadd_h(&x_1, &x_1, &x_1);
        LOG(INFO) << "fmadd_h(1.0, 1.0, 1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_2)) <<
            "fmadd_h(1.0, 1.0, 1.0) failure";

        fp_result_16 = fmsub_h(&x_1, &x_1, &x_1);
        LOG(INFO) << "fmsub_h(1.0, 1.0, 1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), 0) <<
            "fmsub_h(1.0, 1.0, 1.0) failure";

        fp_result_16 = fnmsub_h(&x_1, &x_1, &x_1);
        LOG(INFO) << "fnmsub_h(1.0, 1.0, 1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), 0) <<
            "fmsub_h(1.0, 1.0, 1.0) failure";

        fp_result_16 = fmv_h(&x_1);
        LOG(INFO) << "fmv_h(1.0) = 0x" << std::hex << fp16_as_short(fp_result_16);
        EXPECT_EQ(fp16_as_short(fp_result_16), fp16_as_short(x_1)) << 
            "fmv_h(1.0) failure";
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
    //FLAGS_minloglevel = 1;
    GTEST_FLAG_SET(death_test_style, "fast");
    return RUN_ALL_TESTS();
}
