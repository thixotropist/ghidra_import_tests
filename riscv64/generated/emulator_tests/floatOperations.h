#ifndef FLOAT_OPERATIONS
#define FLOAT_OPERATIONS
#include <stdint.h>

typedef float _fp16;

/// @brief return a 32 bit float as int32 without conversion
static inline int32_t fp32_as_int(float x)
{
    union
    {
        int32_t asInt;
        float asFloat;
    } c;
    c.asFloat = x;
    return c.asInt;
}

/// @brief return a 16 bit float as int16 without conversion
static inline int16_t fp16_as_short(_fp16 x)
{
    union
    {
        int16_t asShort[2];
        float asFloat;
    } c;
    c.asFloat = x;
    return c.asShort[0];
}

/// @brief return a 16 bit float as int32 without conversion
static inline int32_t fp16_as_int(_fp16 x)
{
    union
    {
        int32_t asInt;
        float asFloat;
    } c;
    c.asFloat = x;
    return c.asInt;
}

/// @brief return an int16 as 16 bit float without conversion
static inline _fp16 short_as_fp16(int16_t x)
{
    union
    {
        short asShort[2];
        float asFp16;
    } c;
    c.asShort[0] = x;
    c.asShort[1] = 0xffff;
    return c.asFp16;
}

/// @brief return an int32 as 16 bit float without conversion
static inline _fp16 int_as_fp16(int32_t x)
{
    union
    {
        int32_t asInt;
        float asFp16;
    } c;
    c.asInt = x;
    return c.asFp16;
}

extern float flw(const float* x);
extern int32_t fcvt_w_s(const float* x);
extern uint32_t fcvt_wu_s(const float* x);
extern int32_t fcvt_w_d(const double* x);
extern uint32_t fcvt_wu_d(const double* x);
extern float fcvt_s_w(const int32_t* i);
extern float fcvt_s_wu(const uint32_t* i);
extern float fcvt_s_d(const double* x);
extern double fcvt_d_s(const float* x);
extern double fcvt_d_w(const int32_t* i);
extern double fcvt_d_wu(const uint32_t* j);
extern int32_t fmv_x_w(const float* x);
extern float fmv_w_x(const int32_t* i);
extern _fp16 flh(const _fp16* x);
extern void fsh(const _fp16* dest, _fp16 src);
extern int32_t fmv_x_h(const _fp16* param_1);
extern _fp16 fmv_h_x(const int16_t* param_1);
extern float fcvt_s_h(const _fp16* x);
extern double fcvt_d_h(const _fp16* x);
extern _fp16 fcvt_h_s(const float* x);
extern _fp16 fcvt_h_d(const double* x);
extern int32_t fcvt_w_h(const _fp16* x);
extern unsigned int fcvt_wu_h(const _fp16* x);
extern _fp16 fcvt_h_w(const int32_t* x);
extern _fp16 fcvt_h_wu(const uint32_t* x);
extern int64_t fcvt_l_h(const _fp16* x);
extern uint64_t fcvt_lu_h(const _fp16* x);
extern _fp16 fadd_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fsub_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fmul_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fdiv_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fmin_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fmax_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fsqrt_h(const _fp16 *param_1);
extern _fp16 fsgnj_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fsgnjn_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fsgnjx_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fabs_h(const _fp16 *param_1);
extern _fp16 fneg_h(const _fp16 *param_1);
extern uint32_t fclass_h(const _fp16 *param_1);
extern int32_t feq_h(const _fp16 *param_1, const _fp16 *param_2);
extern int32_t fle_h(const _fp16 *param_1, const _fp16 *param_2);
extern int32_t fgt_h(const _fp16 *param_1, const _fp16 *param_2);
extern _fp16 fmadd_h(const _fp16 *param_1, const _fp16 *param_2, const _fp16 *param_3);
extern _fp16 fnmadd_h(const _fp16 *param_1, const _fp16 *param_2, const _fp16 *param_3);
extern _fp16 fmsub_h(const _fp16 *param_1, const _fp16 *param_2, const _fp16 *param_3);
extern _fp16 fnmsub_h(const _fp16 *param_1, const _fp16 *param_2, const _fp16 *param_3);
extern _fp16 fmv_h(const _fp16 *param_1);


#endif /* FLOAT_OPERATIONS */
