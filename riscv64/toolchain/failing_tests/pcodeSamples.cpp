#include <math.h>
#include <iostream>
#include <glog/logging.h>
bool test_integer_scalar_vector_move() {
    ///@ exercise integer scalar moves into and out of a vector register
    int x = 1;
    int y = 0;
    int z = 0;
    // set vector mode to something simple
    __asm__ __volatile__ ("vsetivli zero,1,e32,m1,ta,ma\n\t");
    // execute both instructions to set y:= x
    __asm__ __volatile__ ("vmv.s.x  v1, %1\n\t" "vmv.x.s  %0, v1"\
                          : "=r" (y) \
                          : "r" (x) );
    __asm__ __volatile__ ("vmv.v.i  v1, 2\n\t" "vmv.x.s  %0, v1"\
                          : "=r" (z) \
                          );
    LOG(INFO) << "vmv.v.i result = " << z;
    return (x==y) && (z==2);
}

bool test_fmv_x_w() {
    // The fmv.x.w instruction moves the most significant 32 bits of a floating point
    // register into a regular register, without numeric conversion
    float x= 123.4;
    int y;
    __asm__ __volatile__ ("fmv.x.w  %0, %1"\
                          : "=r" (y) \
                          : "f" (x) );
    LOG(INFO) << "fmv.x.w result = " << y;
    return y==0x42f6cccd;
}

bool test_fmv_w_x() {
    // The fmv.w.x instruction moves the lower 32 bits of a regular register into the most significant 32 bits of a floating point
    // register, without numeric conversion
    int x = 0x42f6cccd;
    float y;
    __asm__ __volatile__ ("fmv.w.x  %0, %1"\
                          : "=f" (y) \
                          : "r" (x) );
    LOG(INFO) << "fmv.w.x result = " << y;  
    LOG(INFO) << "fmv.w.x residual = " << fabs(y - 123.4);  
    return fabs(y - 123.4) < 0.00001;
}

bool test_vmv1r_v(){
    // copy one vector register to another
    int z;
    // set vector mode to something simple
    __asm__ __volatile__ ("vsetivli zero,1,e32,m1,ta,ma\n\t");
    // v1[0] := 3; v2 := v1; z = v2[0];
    __asm__ __volatile__ ("vmv.v.i  v1, 3\n\t" \
                          "vmv1r.v  v2,v1\n\t"  \
                          "vmv.x.s  %0, v2"
                          : "=r" (z) \
                          );
    LOG(INFO) << "vmv1r.v result = " << z;
    return z==3;                     
}

bool test_vid_v() {
    // copy a register into memory
    unsigned char x[16];
    unsigned char* px = x;
    // set vector mode to 16 unsigned integers
    __asm__ __volatile__ ("vsetivli zero,16,e8,m1,ta,ma\n\t");
    // generate a vector of integers
    __asm__ __volatile__ ("vid.v  v1 \n\t" );
    // copy those integers into x
    __asm__ __volatile__ ("vs1r.v v1,(%0) \n\t" \
                         : \
                         : "r" (px) );
    LOG(INFO) << "vs1r.v result = [" << static_cast<int>(x[0]) << ", " << static_cast<int>(x[15]) << "]";
    return (x[0]==0) & (x[15]==15);
}