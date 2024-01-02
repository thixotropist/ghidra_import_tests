#include "common.h"
#include <string.h>

int main() {
  const int N = 127;
  const uint32_t seed = 0xdeadbeef;
  srand(seed);

  // data gen
  double A[N];
  gen_rand_1d(A, N);

  // compute
  double copy[N];
  memcpy(copy, A, sizeof(A));
  
  // print
  printf("%f\n", copy[1]);
}