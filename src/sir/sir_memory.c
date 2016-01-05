#include <stdint.h>
#include <stddef.h>

typedef uint64_t align_t;

union header {
  struct {
    union header *ptr; /* next block if on free list */
    uint64_t size;     /* size of this block */
  } s;
  align_t x;           /* to force alignment of blocks */
};

typedef union header Header;

static Header base;    /* empty list before init */
static Header *freep = NULL; /* start of free list */

typedef struct {
  uint8_t *heap_buf_start;
  uint64_t heap_buf_size;
  uint8_t *heap_buf_current;
} sir_memory_context_t;

static sir_memory_context_t sir_memory_context;

void init_memory(uint8_t* heap_buf,
                 uint64_t heap_size)
{
  sir_memory_context.heap_buf_start   = heap_buf;
  sir_memory_context.heap_buf_current = heap_buf;
  sir_memory_context.heap_buf_size    = heap_size;
}

Header *morecore(uint64_t nunits)
{
  uint64_t nbytes = nunits * sizeof(Header);
  if ((sir_memory_context.heap_buf_start + 
       sir_memory_context.heap_buf_size -
       sir_memory_context.heap_buf_current) >= nbytes) 
  {
    sir_memory_context.heap_buf_current += nbytes;
    return ((Header *) (sir_memory_context.heap_buf_current - nbytes));
  } else {
    return NULL;
  }
}

void *sir_malloc(uint64_t nbytes)
{
  Header *p, *prevp; /* 2 linked pointers in linked list */
  uint64_t nunits = (nbytes + sizeof(Header) - 1) / sizeof(Header) + 1;   

  if ((prevp = freep) == NULL) {
    prevp = &base;
    freep = prevp;
    base.s.ptr = freep;
    //base.s.ptr = freep = prevp = &base;
    base.s.size = 0;
  }
  for (p = prevp->s.ptr; ; prevp = p, p = p->s.ptr) {
    if (p->s.size >= nunits) {
      if (p->s.size == nunits) {
        prevp->s.ptr = p->s.ptr;
      } else {
        p->s.size -= nunits;
        p += p->s.size;
        p->s.size = nunits;
      }
      freep = prevp;
      return (void *) (p+1);
    }
    if (p == freep) { /* looped around the free list */
      if ((p = morecore(nunits)) == NULL) { /* still no luck, so ask for more */
        return NULL; /* out of memory */
      }
    }
  }
}

void sir_free(void *ap)
{
  Header *bp, *p;
  
  bp = (Header *) ap - 1;
  for (p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
  {
    if (p >= p->s.ptr && (bp > p || bp < p->s.ptr)) 
    { 
      break; 
    }
  }

  if (bp + bp->s.size == p->s.ptr) {
    bp->s.size += p->s.ptr->s.size;
    bp->s.ptr   = p->s.ptr->s.ptr;
  } else {
    bp->s.ptr = p->s.ptr;
  }

  if (p + p->s.size == bp) {
    p->s.size += bp->s.size;
    p->s.ptr = bp->s.ptr;
  } else {
    p->s.ptr = bp;
  }
  freep = p;
}

