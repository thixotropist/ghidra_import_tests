#ifndef FLOAT_CONVERSIONS
#define FLOAT_CONVERSIONS

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
#endif
