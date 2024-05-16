#include "common.h"
#include <riscv_vector.h>

// accumulate and reduce
void reduce(double *a, double *b, double *result_sum,
                     int *result_count, int n) {
  int count = 0;
  double s = 0;
  for (int i = 0; i < n; ++i) {
    if (a[i] != 42.0) {
      s += a[i] * b[i];
      count++;
    }
  }

  *result_sum = s;
  *result_count = count;
}

int main() {
  const int N = 31;
  uint32_t seed = 0xdeadbeef;
  srand(seed);

  // data gen
  double A[N], B[N];
  gen_rand_1d(A, N);
  gen_rand_1d(B, N);

  // compute
  double sum;
  int count;
  reduce(A, B, &sum, &count, N);
    // compare
  printf("%f\n", sum);
}