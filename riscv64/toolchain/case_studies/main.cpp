#include <iostream>
#include <cstring>
#include <glog/logging.h>
#include "mocks.h"

float src[32];
struct block_q8_0 dest[1];

void print_block(const block_q8_0* b){
    LOG(INFO)<< "Testing returned: " << "\n";
    LOG(INFO)<< "\tq0 = 0x" << std::hex << b[0].d << ", ";
    for (int i = 0; i < 32; i++) {
        LOG(INFO)<< "0x" << (0xff & static_cast<int>(b[0].qs[i])) << ", ";
    }
    LOG(INFO)<< "\n";
}

void mystery(int k) {
    int result = (int)(((uint)((int)k >> 0x1f) >> 0x1b) + (int)k) >> 5;
    LOG(INFO)<< "mystery(" << k << ") = " << result << "\n";
    LOG(INFO)<< "\tadjustment = " << (int)(((uint)((int)k >> 0x1f) >> 0x1b)) << "\n";
}

int main() {

    google::InitGoogleLogging("unit tests");
    LOG(INFO) << "Logging System Initialized.";

    for (int i=0; i < 32; i++) {
        src[i] = i % 2 ? float(-i) : float(i);
    }
    LOG(INFO)<< "Testing whisper mocks\n";
    mystery(0x20);
    mystery(0x40);
    mystery(0xffff0000);
    mystery(-0x20);
    mystery(-0x40);
    LOG(INFO)<< "Testing synthetic riscv intrinsics\n";
    LOG(INFO)<< "\tsrc=" << src[0] << ", " << src[1] << ", " << src[2] << ", " << src[3] << "\n";

    quantize_row_q8_0(src, dest, 32);
    print_block(dest);
    memset(dest, 0, sizeof(dest));
    LOG(INFO)<< "Testing vectorized simple loops\n";
    quantize_row_q8_0_reference(src, dest, 32);
    print_block(dest);
    LOG(INFO) << "Logging System Terminated.";
    google::ShutdownGoogleLogging();
    return 0;
}