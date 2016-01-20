#ifndef SIR_LIBSTRING_H
#define SIR_LIBSTRING_H

#include <stdint.h>

int memcmp(const uint8_t *s1, const uint8_t *s2, uint64_t n);
uint8_t * memcpy(uint8_t* region1, const uint8_t* region2, uint64_t n);
uint8_t * memset(uint8_t* dest, uint8_t val, uint64_t len);
uint64_t strlen(const char *str);

#endif /* SIR_LIBSTRING_H */
