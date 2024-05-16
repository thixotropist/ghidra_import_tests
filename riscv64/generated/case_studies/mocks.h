#include <stdint.h>
#include <math.h>
#ifndef MOCKS
#define MOCKS

static const int QK8_0=0x20;
static const float SCALE_MAX = 127.0;
static const short FLAG_MASK = 0xfff;

typedef short fp16_t;
struct block_q8_0 {
    fp16_t d;
    signed char qs[QK8_0];
};

// ref: https://github.com/Maratyszcza/FP16
static inline uint32_t fp32_to_bits(float f) {
    union {
        float as_value;
        uint32_t as_bits;
    } fp32;
    fp32.as_value = f;
    return fp32.as_bits;
}

static inline float fp32_from_bits(uint32_t w) {
    union {
        uint32_t as_bits;
        float as_value;
    } fp32;
    fp32.as_bits = w;
    return fp32.as_value;
}

static inline fp16_t ggml_compute_fp32_to_fp16(float f) {
    const float scale_to_inf = 0x1.0p+112f;
    const float scale_to_zero = 0x1.0p-110f;

    float base = (fabsf(f) * scale_to_inf) * scale_to_zero;

    const uint32_t w = fp32_to_bits(f);
    const uint32_t shl1_w = w + w;
    const uint32_t sign = w & UINT32_C(0x80000000);
    uint32_t bias = shl1_w & UINT32_C(0xFF000000);
    if (bias < UINT32_C(0x71000000)) {
        bias = UINT32_C(0x71000000);
    }

    base = fp32_from_bits((bias >> 1) + UINT32_C(0x07800000)) + base;
    const uint32_t bits = fp32_to_bits(base);
    const uint32_t exp_bits = (bits >> 13) & UINT32_C(0x00007C00);
    const uint32_t mantissa_bits = bits & UINT32_C(0x00000FFF);
    const uint32_t nonsign = exp_bits + mantissa_bits;
    return (sign >> 16) | (shl1_w > UINT32_C(0xFF000000) ? UINT16_C(0x7E00) : nonsign);
}
#ifdef __cplusplus
extern "C" {
#endif
void quantize_row_q8_0(const float* x, block_q8_0* y, int k);
void quantize_row_q8_0_reference(const float* x, block_q8_0* y, int k);
#ifdef __cplusplus
}
#endif
#endif /* MOCKS */