#ifndef SIR_MEMORY_H
#define SIR_MEMORY_H

void init_memory(uint8_t* heap_buf, uint64_t heap_size);
void *sir_malloc(uint64_t nbytes);
void sir_free(void *ap);

#endif /* SIR_MEMORY_H */
