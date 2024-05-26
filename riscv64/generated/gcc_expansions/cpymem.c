extern void *memcpy(void *__restrict dest, const void *__restrict src, __SIZE_TYPE__ n);
extern void *memmov(void *dest, const void *src, __SIZE_TYPE__ n);

/* invoke memcpy with dynamic size */
void cpymem_1 (void *a, void *b, __SIZE_TYPE__ l)
{
  memcpy (a, b, l);
}

/* invoke memcpy with known size and aligned pointers */
extern struct { __INT32_TYPE__ a[16]; } a_a, a_b;

void cpymem_2 ()
{
  memcpy (&a_a, &a_b, sizeof a_a);
}

typedef struct { char c[16]; } c16;
typedef struct { char c[32]; } c32;
typedef struct { short s; char c[30]; } s16;

/* copy fixed 128 bits of memory */
void cpymem_3 (c16 *a, c16* b)
{
  *a = *b;
}

/* copy fixed 256 bits of memory */
void cpymem_4 (c32 *a, c32* b)
{
  *a = *b;
}

/* copy fixed 256 bits of memory */
void cpymem_5 (s16 *a, s16* b)
{
  *a = *b;
}

/* memmov allows overlap - don't vectorize or inline */
void movmem_1(void *a, void *b, __SIZE_TYPE__ l)
{
  memmov (a, b, l);
}
