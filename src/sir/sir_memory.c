#include <stdint.h>
#include <stddef.h>
#include "sir_memory.h"

static Header base;    /* empty list before init */
static Header *freep = NULL; /* start of free list */
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
  Header *result;

  if ((sir_memory_context.heap_buf_start + 
       sir_memory_context.heap_buf_size -
       sir_memory_context.heap_buf_current) >= nbytes) 
  {
    result = (Header *) sir_memory_context.heap_buf_current;
    result->s.size = nunits;
    sir_free((void *) (result + 1));
    sir_memory_context.heap_buf_current += nbytes;
    return freep;
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
  
  bp = (Header *)ap - 1;
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

