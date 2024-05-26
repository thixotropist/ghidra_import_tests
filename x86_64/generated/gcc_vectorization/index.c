#include "common.h"
// index arithmetic
void index(double *a, double *b, double *c, int n) {
  for (int i = 0; i < n; ++i) {
    a[i] = b[i] + (double)i * c[i];
  }
}

int main() {
  const int N = 31;
  const uint32_t seed = 0xdeadbeef;
  srand(seed);

  // data gen
  double B[N], C[N];
  gen_rand_1d(B, N);
  gen_rand_1d(C, N);

  // compute
  double result[N];
  index(result, B, C, N);
    // compare
  printf("%f\n", result[N]);
}