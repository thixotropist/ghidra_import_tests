char bssString[4096];
#include <stdio.h>
int
main (void)
{
  // exercise store into .bss with small offset
  bssString[8] = 0;
  // exercise store into .bss with 12 bit offset
  bssString[2049] = 0;
  // reference bssString to prevent optimization erasure
  printf(bssString);
  return 0;
}
