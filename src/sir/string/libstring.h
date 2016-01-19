#ifndef SIR_LIBSTRING_H
#define SIR_LIBSTRING_H

#include <stdint.h>

int memcmp(const uint8_t *s1, const uint8_t *s2, uint64_t n);
void *memcpy(uint8_t* region1, const uint8_t* region2, uint64_t n);
void* memset(void* dest, int val, uint64_t len);
uint64_t strlen(const char *str);

#endif /* SIR_LIBSTRING_H */
