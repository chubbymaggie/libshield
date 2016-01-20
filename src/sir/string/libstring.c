#include <stdint.h>

int memcmp(const uint8_t *s1, const uint8_t *s2, uint64_t n)
{
  unsigned char u1, u2;

  for ( ; n-- ; s1++, s2++) {
    u1 = * (unsigned char *) s1;
    u2 = * (unsigned char *) s2;
    if ( u1 != u2) {
      return (u1-u2);
    }
  }
  return 0;
}

/*@ requires n > 0;
    requires \separated(dst+ (0..n-1), src+ (0..n-1));
    requires (dst < dst + n) && (src < src + n) && (dst + n <= src || src + n <= dst);
    requires \valid(dst+ (0..n-1)) && \valid(src+ (0..n-1));
    ensures  \valid(dst+ (0..n-1)) && \valid(src+ (0..n-1));
    ensures \forall uint64_t i; (0 <= i <= n-1) ==> (dst[i] == src[i]);
 */
uint8_t* memcpy(uint8_t* dst, const uint8_t* src, uint64_t n)
{
  uint8_t *local_dst = dst;
  //@ assert (local_dst == dst); 
  const uint8_t *local_src = src;
  //@ assert (local_src == src); 
  
  /*@ loop assigns i, dst[0 .. n-1], local_dst, local_src;
      loop invariant 0 <= i <= n;
      loop invariant local_dst == dst + i;
      loop invariant local_src == src + i;
      loop invariant \forall uint64_t j; (0 <= j < i) ==> (dst[j] == src[j]); 
   */
  for (uint64_t i = 0; i < n; i++) {
    *local_dst++ = *local_src++;
  }

  return dst;
}

/*@ requires n > 0 && (dst < dst + n);
    requires \valid(dst+ (0..n-1));
    ensures  \valid(dst+ (0..n-1));
    ensures \forall uint64_t i; (0 <= i <= n-1) ==> (dst[i] == val);
    ensures \result == \old(dst);
 */
uint8_t* memset(uint8_t* dst, uint8_t val, uint64_t n)
{
  uint8_t *ptr = dst;
  //@ assert (ptr == dst); 

  /*@ loop assigns i, ptr, dst[0..n-1];
      loop invariant 0 <= i <= n;
      loop invariant ptr == dst + i;
      loop invariant \forall uint64_t j; (0 <= j < i) ==> (dst[j] == val); 
   */
  for (uint64_t i = 0; i < n; i++)
  {
    *ptr++ = val;
  }
  return dst;
}

uint64_t strlen(const char *str)
{
  const char *s;
  for (s = str; *s; ++s)
    ;
  return (s - str);
}
