typedef long unsigned int size_t;
int
my_str_cmp (const char *s1, const char *s2)
{
  s1 = __builtin_assume_aligned (s1, 4096);
  s2 = __builtin_assume_aligned (s2, 4096);
  return __builtin_strcmp (s1, s2);
}
int
my_str_cmp_const (const char *s1)
{
  s1 = __builtin_assume_aligned (s1, 4096);
  return __builtin_strcmp (s1, "foo");
}

/* Emits 6+1 th.tstnbz instructions.  */

int
my_strn_cmp (const char *s1, const char *s2)
{
  s1 = __builtin_assume_aligned (s1, 4096);
  s2 = __builtin_assume_aligned (s2, 4096);
  return __builtin_strncmp (s1, s2, 42);
}

/* Note expanded because the backend does not know the size of "foo".  */

int
my_strn_cmp_const (const char *s1, size_t n)
{
  s1 = __builtin_assume_aligned (s1, 4096);
  return __builtin_strncmp (s1, "foo", n);
}

/* Emits 6+1 th.tstnbz instructions.  */

int
my_strn_cmp_bounded (const char *s1, const char *s2)
{
  s1 = __builtin_assume_aligned (s1, 4096);
  s2 = __builtin_assume_aligned (s2, 4096);
  return __builtin_strncmp (s1, s2, 42);
}
