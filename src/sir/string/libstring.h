#ifndef SIR_LIBSTRING_H
#define SIR_LIBSTRING_H

#include <stdint.h>

int memcmp(const void *s1, const void *s2, uint64_t n);
void * memcpy(void* region1, const void* region2, uint64_t n);
void * memset(void* dest, uint8_t val, uint64_t len);
uint64_t strlen(const char *str);

#endif /* SIR_LIBSTRING_H */
