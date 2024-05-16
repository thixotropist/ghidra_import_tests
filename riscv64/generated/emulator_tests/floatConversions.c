#include <stdio.h>
#include "floatConversions.h"

int fcvt_w_s(float* x) {
    return (int)*x;
}

unsigned int fcvt_wu_s(float* x) {
    return (unsigned int)*x;
}

int fcvt_w_d(double* x) {
    return (int)*x;
}

unsigned int fcvt_wu_d(double* x) {
    return (unsigned int)*x;
}

float fcvt_s_w(int* i) {
    return (float)*i;
}

float fcvt_s_wu(unsigned int* i) {
    return (float)*i;
}

float fcvt_s_d(double* x) {
    return (float)*x;
}

double fcvt_d_s(float* x) {
    return (double)*x;
}

double fcvt_d_w(int* i) {
    return (double)*i;
}

double fcvt_d_wu(unsigned int* j) {
    return (double)*j;
}

// Move the single-precision value in floating-point register rs1
// represented in IEEE 754-2008 encoding to the lower 32 bits of
// integer register rd.
int fmv_x_w(float* x) {
    int val;
    float src = *x;

    __asm__ __volatile__ (
        "fmv.x.w  %0, %1" \
        : "=r" (val) \
        : "f" (src));
    return val;
}

// Move the single-precision value encoded in IEEE 754-2008 standard encoding
// from the lower 32 bits of integer register rs1 to the floating-point register rd.
float fmv_w_x(int* i) {
    float val;
    int src = *i;
    __asm__ __volatile__ (
        "fmv.w.x  %0, %1" \
        : "=f" (val) \
        : "r" (src));
    return val;
}

///@brief this never-called function helps Ghidra establish key function signatures
void dummyCalls() {
    float x = 1.0;
    double xd = 1.0;
    int i = 1;
    unsigned int j = 1;
    printf("%d\n", fcvt_w_s(&x));
    printf("%d\n", fcvt_wu_s(&x));
    printf("%d\n", fcvt_w_d(&xd));
    printf("%d\n", fcvt_wu_d(&xd));
    printf("%f\n", fcvt_s_w(&i));
    printf("%f\n", fcvt_s_wu(&j));
    printf("%f\n", fcvt_s_d(&xd));
    printf("%f\n", fcvt_d_s(&x));
    printf("%f\n", fcvt_d_w(&i));
    printf("%f\n", fcvt_d_wu(&j));
    printf("%d\n", fmv_x_w(&x));
    printf("%f\n", fmv_w_x(&i));
}