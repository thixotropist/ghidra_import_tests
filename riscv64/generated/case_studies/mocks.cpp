
#if defined(__riscv_v_intrinsic)
#include <riscv_vector.h>
#endif
#include <iostream>
#include <assert.h>
#include "mocks.h"

void quantize_row_q8_0(const float * __restrict x, block_q8_0 * __restrict y, int k)
{
    /// load from src in blocks of BLOCK_SIZE
    /// find max of absolute values
    /// scale by 127.0/max(block)
    
#if defined(__riscv_v_intrinsic)
    size_t vl = __riscv_vsetvl_e32m4(QK8_0);
    int nb = k / QK8_0;
    for (int i = 0; i < nb; i++) {
        // load elements
        vfloat32m4_t v_x   = __riscv_vle32_v_f32m4(x+i*QK8_0, vl);

        vfloat32m4_t vfabs = __riscv_vfabs_v_f32m4(v_x, vl);
        vfloat32m1_t tmp   = __riscv_vfmv_v_f_f32m1(0.0f, vl);
        vfloat32m1_t vmax  = __riscv_vfredmax_vs_f32m4_f32m1(vfabs, tmp, vl);
        float amax = __riscv_vfmv_f_s_f32m1_f32(vmax);
        const float d = amax / ((1 << 7) - 1);
        const float id = d ? 1.0f/d : 0.0f;

        y[i].d = ggml_compute_fp32_to_fp16(d);
        vfloat32m4_t x0 = __riscv_vfmul_vf_f32m4(v_x, id, vl);

        // convert to integer
        vint16m2_t   vi = __riscv_vfncvt_x_f_w_i16m2(x0, vl);
        vint8m1_t    vs = __riscv_vncvt_x_x_w_i8m1(vi, vl);

        // store result
        __riscv_vse8_v_i8m1(y[i].qs , vs,  vl);
    }
#else
    quantize_row_q8_0_reference(x,y,k);
#endif
    return;
}

void quantize_row_q8_0_reference(const float * __restrict x, block_q8_0 * __restrict y, int k) {
    assert(k % QK8_0 == 0);
    const int nb = k / QK8_0;

    for (int i = 0; i < nb; i++) {
        float amax = 0.0f; // absolute max

        for (int j = 0; j < QK8_0; j++) {
            const float v = x[i*QK8_0 + j];
            amax = fmax(amax, fabsf(v));
        }
        const float d = amax / ((1 << 7) - 1);
        const float id = d ? 1.0f/d : 0.0f;
        y[i].d = ggml_compute_fp32_to_fp16(d);

        for (int j = 0; j < QK8_0; ++j) {
            const float x0 = x[i*QK8_0 + j]*id;
            y[i].qs[j] = roundf(x0);
        }
    }
}