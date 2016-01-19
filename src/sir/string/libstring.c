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
    requires 
    requires \valid((uint8_t*)region1+(0..n-1)) && \valid((uint8_t *) region2+(0..n-1));
    ensures  \valid((uint8_t*)region1+(0..n-1)) && \valid((uint8_t *) region2+(0..n-1));
 */
void *memcpy(void* region1, const void* region2, uint64_t n)
{
  uint8_t *dst = (uint8_t *) region1;
  const uint8_t *src = (const uint8_t *) region2;
  //@ assert (dst == (uint8_t*) region1); 
  //@ assert (src == (uint8_t*) region2); 
  for (uint64_t i = 0; i < n; i++) {
    *dst++ = *src++;
  }

  return region1;
}

/*@ requires n > 0; 
    requires \valid(p+ (0..n−1)); 
    ensures \forall int i; 0 <= i <= n−1 ==> p[i] == \old(p[i]); 
    ensures \forall int i; 0 <= i <= n−1 ==> \result >= p[i]; 
    ensures \exists int e; 0 <= e <= n−1 && \result == p[e]; 
*/ 
int max_seq(int* p, int n) { 
  int res = *p; 
  //@ ghost int e = 0; 
  /*@ loop invariant \forall integer j; 
           0 <= j < i ==> res >= \at(p[j],Pre); 
      loop invariant 
           \valid(\at(p,Pre)+e) && \at(p,Pre)[e] == res; 
      loop invariant 0<=i<=n; 
      loop invariant p==\at(p,Pre)+i; 
      loop invariant 0<=e<n; 
  */ 
  for(int i = 0; i < n; i++) { 
    if (res < *p) { 
      res = *p; 
      //@ ghost e = i; 
    } 
    p++; 
  } 
  return res; 
} 

void* memset(void* dest, int val, uint64_t len)
{
  uint8_t *ptr = (uint8_t *) dest;
  while (len-- > 0)
  {
    *ptr++ = val;
  }
  return dest;
}
/*
char * strstr ( const char *haystack, const char *needle)
{
    if (haystack == NULL || needle == NULL) {
        return NULL;
    }

    for ( ; *haystack; haystack++) {
        // Is the needle at this point in the haystack?
        const char *h, *n;
        for (h = haystack, n = needle; *h && *n && (*h == *n); ++h, ++n) {
            // Match is progressing
        }
        if (*n == '\0') {
            // Found match!
            return (char *) haystack;
        }
        // Didn't match here.  Try again further along haystack.
    }
    return NULL;
}
*/

uint64_t strlen(const char *str)
{
  const char *s;
  for (s = str; *s; ++s)
    ;
  return (s - str);
}
