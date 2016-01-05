#ifndef SIR_MEMORY_H
#define SIR_MEMORY_H

typedef uint64_t align_t;

typedef union header {
  struct {
    union header *ptr; /* next block if on free list */
    uint64_t size;     /* size of this block */
  } s;
  align_t x;           /* to force alignment of blocks */
} Header;

typedef struct {
  uint8_t *heap_buf_start;
  uint64_t heap_buf_size;
  uint8_t *heap_buf_current;
} sir_memory_context_t;

void init_memory(uint8_t* heap_buf, uint64_t heap_size);
void *sir_malloc(uint64_t nbytes);
void sir_free(void *ap);

#endif /* SIR_MEMORY_H */
