extern void *memset(void *dest, int c, __SIZE_TYPE__ n);
extern void bzero(void *dest, __SIZE_TYPE__ n);

void *setmem1(void *dest, __SIZE_TYPE__ n) {
    return memset(dest, 0, n);
}
void setmem2(void *dest, __SIZE_TYPE__ n) {
    bzero(dest, n);
}
