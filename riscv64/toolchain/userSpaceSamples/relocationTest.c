char bssString[4096];
__thread char threadLocalString[4096];
#include <stdio.h>
int
main (void)
{
  // exercise store into .bss with small offset
  bssString[8] = 0;
  // exercise store into .bss with 12 bit offset with high order bit set
  bssString[2049] = 0;
  // reference bssString to prevent optimization erasure
  printf(bssString);
  // repeat with thread local storage
  threadLocalString[8] = 0;
  threadLocalString[2049] = 0;
  printf(threadLocalString);
  return 0;
}
