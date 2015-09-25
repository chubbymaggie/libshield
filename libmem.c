#include <string.h>

void * memcpy(void *dst, const void *src, size_t length)
{
  unsigned int i;
  unsigned char *dp = dst;
  unsigned const char *sp = src;

  for (i=0; i<length; i++)
    *dp++ = *sp++;
  return dst;
}

void* memset (void* dest, int val, size_t len) 
{
  unsigned char *ptr = (unsigned char*)dest;
  while (len-- > 0)
    *ptr++ = val; 
  return dest;
}

int memcmp(const void *s1, const void *s2, size_t n)
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

size_t strlen(const char *str)
{
  const char *s;
  for (s = str; *s; ++s)
    ;
  return (s - str);
}

void exit(int status)
{
  __asm("int3");
}
