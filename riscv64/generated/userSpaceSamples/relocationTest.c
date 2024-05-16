/**
 * @file relocationTest.c
 * @brief generate riscv-64 relocations and local symbols in an object file.
 */

/// @brief an object in blank storage (bss) that needs 12 bit offsets
char bssString[4096];
/// @brief same as above, but with a symbol name requiring UTF-8 encoding
char ว่างเปล่า[4096];
/// @brief an thread-local object accessible via the tp register
__thread char threadLocalString[4096];
#include <stdio.h>

/// @brief a trivial function symbol requiring UTF8
void ตรวจสอบ() {
  printf("Inspected\n");
}

/// @brief an example of inline riscv64 atomics and local backreferences
/// derived from the kernel function futex_atomic_cmpxchg_inatomic

// uses the load reserved word with acquire/release instruction and
// the store conditional word with acquire/release instruction
static inline int
backrefDemo(unsigned int *uval, unsigned int *uaddr,
                              unsigned int oldval, unsigned int newval)
{
        int ret = 0;
        unsigned int val;
        unsigned int* tmp;
        register unsigned int* u = uaddr;

        // 

        __asm__ __volatile__ (
        "1:     lr.w.aqrl %[v],(%[u])                   \n"
        "       bne %[v],%z[ov],3f                      \n"
        "2:     sc.w.aqrl %[t],%z[nv],(%[u])            \n"
        "       bnez %[t],1b                            \n"
        "3:                                             \n"
        : [r] "+r" (ret), [v] "=&r" (val), [u] "=&r" (u), [t] "=&r" (tmp)
        : [ov] "Jr" (oldval), [nv] "Jr" (newval)
        : "memory");
        *uval = val;
        return ret;
}

int
main (void)
{
  // exercise store into .bss with small offset
  bssString[8] = 0;
  // exercise store into .bss with 12 bit offset with high order bit set
  bssString[2049] = 0;
  // reference bssString to prevent optimization erasure
  printf(bssString);
  // repeat with a unicode global symbol
  ว่างเปล่า[8] = 0;
  // exercise store into .bss with 12 bit offset with high order bit set
  ว่างเปล่า[2049] = 0;
  // reference bssString to prevent optimization erasure
  printf(ว่างเปล่า);
  // repeat with thread local storage
  threadLocalString[8] = 0;
  threadLocalString[2049] = 0;
  printf(threadLocalString);

  // invoke the inline assembly with nonsense arguments twice
  unsigned int result;
  unsigned int ref;
  int tmp = backrefDemo(&result, &ref, 2, 3);
  tmp = backrefDemo(&result, &ref, 3, 4);
  printf("assembly code produced %d\n", tmp);
  return 0;
}
