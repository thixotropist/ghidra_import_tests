#ifndef FLOAT_OPERATIONS
#define FLOAT_OPERATIONS

typedef float _fp16;

static inline int fp32_as_int(float x)
{
    union
    {
        int asInt;
        float asFloat;
    } c;
    c.asFloat = x;
    return c.asInt;
}

static inline short fp16_as_short(_fp16 x)
{
    union
    {
        short asShort[2];
        float asFloat;
    } c;
    c.asFloat = x;
    return c.asShort[0];
}

static inline int fp16_as_int(_fp16 x)
{
    union
    {
        int asInt;
        float asFloat;
    } c;
    c.asFloat = x;
    return c.asInt;
}

static inline _fp16 short_as_fp16(short x)
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

static inline _fp16 int_as_fp16(int x)
{
    union
    {
        int asInt;
        float asFp16;
    } c;
    c.asInt = x;
    return c.asFp16;
}

extern float flw(float* x);
extern int fcvt_w_s(float* x);
extern unsigned int fcvt_wu_s(float* x);
extern int fcvt_w_d(double* x);
extern unsigned int fcvt_wu_d(double* x);
extern float fcvt_s_w(int* i);
extern float fcvt_s_wu(unsigned int* i);
extern float fcvt_s_d(double* x);
extern double fcvt_d_s(float* x);
extern double fcvt_d_w(int* i);
extern double fcvt_d_wu(unsigned int* j);
extern int fmv_x_w(float* x);
extern float fmv_w_x(int* i);
extern float fcvt_s_h(_fp16* x);
extern double fcvt_d_h(_fp16* x);
extern _fp16 fcvt_h_s(float* x);
extern _fp16 fcvt_h_d(double* x);
#endif /* FLOAT_OPERATIONS */
