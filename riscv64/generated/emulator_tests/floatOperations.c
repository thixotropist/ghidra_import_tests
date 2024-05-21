#include <stdio.h>
#include "floatOperations.h"


float flw(float* x) {
    return *x;
}

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

// Convert a half-precision floating-point number to a single-precision floating-point number
float fcvt_s_h(_fp16* x) {
    float val;
    _fp16 src = *x;
    __asm__ __volatile__ (
        "fcvt.s.h  %0, %1" \
        : "=f" (val) \
        : "f" (src));
    return val;
}

// Convert a half-precision floating-point number to a double-precision floating-point number
double fcvt_d_h(_fp16* x) {
    double val;
    _fp16 src = *x;
    __asm__ __volatile__ (
        "fcvt.d.h  %0, %1" \
        : "=f" (val) \
        : "f" (src));
    return val;
}

// Convert a single-precision floating-point number to a half-precision floating-point number
_fp16 fcvt_h_s(float* x) {
    float src = *x;
    _fp16 val;
    __asm__ __volatile__ (
        "fcvt.h.s  %0, %1" \
        : "=f" (val) \
        : "f" (src));
    return val;
}

// Convert a double-precision floating-point number to a half-precision floating-point number
_fp16 fcvt_h_d(double* x) {
    double src = *x;
    _fp16 val;
    __asm__ __volatile__ (
        "fcvt.h.d  %0, %1" \
        : "=f" (val) \
        : "f" (src));
    return val;
}

///@brief this never-called function helps Ghidra establish key function signatures
void dummyCalls() {
    float x = 1.0;
    double xd = 1.0;
    _fp16 xh = short_as_fp16(0x7fc0);
    int i = 1;
    unsigned int j = 1;
    printf("%f\n", flw(&x));
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
    printf("%f\n", fcvt_s_h(&xh));
    printf("%f\n", fcvt_d_h(&xh));
    printf("%f\n", fcvt_h_s(&x));
    printf("%f\n", fcvt_h_d(&xd));

}