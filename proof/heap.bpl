/**
 * Implements send and recv API
 * Channel state from 0x1000 to 0x2000
 */

 type heap_api_result_t;
 const unique heap_success: heap_api_result_t;
 const unique heap_failure: heap_api_result_t;

/*
typedef struct {
  uint8_t *heap_buf_start;
  uint64_t heap_buf_size;
  uint8_t *heap_buf_current;
} sir_memory_context_t;
*/

/*
typedef struct header {
    struct header *ptr; // next block if on free list
    uint64_t size;      // size of this block
} malloc_header_t;
*/

procedure {:inline 1} init_heap ( heap_buf_start: uint8_ptr_t,
                                  heap_buf_size: uint64_t )
modifies sir_heap_context, freep;
{
  sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 0bv64),
                                    heap_buf_start);
  sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 8bv64),
                                    heap_buf_size);
  sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 16bv64),
                                    PLUS_64(heap_buf_start, 16bv64));
  freep := NULL;
}

procedure {:inline 1} bytes_available_in_heap_buf (size: uint64_t)
returns (result: bool)
requires GT_64(size, 0bv64);
requires AddrInHeapInclusive(LOAD_LE_64(sir_heap_context, PLUS_64(sir_heap_context_ptr_low, 16bv64)));
{
  var heap_buf_current: uint8_ptr_t;
  var heap_buf_size: uint8_ptr_t;
  var heap_buf_start: uint8_ptr_t;

  heap_buf_start   := LOAD_LE_64(sir_heap_context,
                                 PLUS_64(sir_heap_context_ptr_low, 0bv64));
  heap_buf_size    := LOAD_LE_64(sir_heap_context,
                                 PLUS_64(sir_heap_context_ptr_low, 8bv64));
  heap_buf_current := LOAD_LE_64(sir_heap_context,
                                 PLUS_64(sir_heap_context_ptr_low, 16bv64));

  assert GT_64(size, 0bv64);
  result := LE_64(PLUS_64(heap_buf_current, size), PLUS_64(heap_ptr_low, heap_buf_size)) &&
            GE_64(PLUS_64(heap_buf_current, size), heap_buf_current);

  //result := LE_64(PLUS_64(heap_buf_current, size), heap_ptr_high) &&
  //          GE_64(PLUS_64(heap_buf_current, size), heap_buf_current);

  assert result ==>
         (AddrInHeapInclusive(heap_buf_current) &&
          AddrInHeapInclusive(PLUS_64(heap_buf_current, MINUS_64(size,1bv64))));
}

procedure {:inline 1} morecore( nunits: uint64_t )
returns (result: header_ptr_t)
modifies heap, sir_heap_context, freep;
requires LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 8bv64)) == heap_size;
requires LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 0bv64)) == heap_ptr_low;
ensures LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 8bv64)) == heap_size;
ensures LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 0bv64)) == heap_ptr_low;
{
  var nbytes: uint64_t;
  var heap_buf_current: uint8_ptr_t;
  var bytes_available: bool;
  var free_api_result: heap_api_result_t;

  heap_buf_current := LOAD_LE_64(sir_heap_context,
                                 PLUS_64(sir_heap_context_ptr_low, 16bv64));
  nbytes := LSHIFT_64(nunits, 4bv64);

  call bytes_available := bytes_available_in_heap_buf( nbytes );
  if (bytes_available)
  {
    result := heap_buf_current;
    //assert AddrInHeap(PLUS_64(result, 8bv64));
    heap := STORE_LE_64(heap, PLUS_64(result, 8bv64), nunits);
    //call free_api_result := L_free(PLUS_64(result, 8bv64)); //TODO uncomment
    sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 16bv64),
                                    PLUS_64(nbytes, heap_buf_current));
  }
  else { result := NULL; return; }
}

procedure L_malloc( size: uint64_t )
returns (result: heap_api_result_t, region: virtual_addr_t)
requires AddrInHeapInclusive(LOAD_LE_64(sir_heap_context, PLUS_64(sir_heap_context_ptr_low, 16bv64)));
requires LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 8bv64)) == heap_size;
requires LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 0bv64)) == heap_ptr_low;
ensures AddrInHeapInclusive(LOAD_LE_64(sir_heap_context, PLUS_64(sir_heap_context_ptr_low, 16bv64)));
ensures LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 8bv64)) == heap_size;
ensures LOAD_LE_64(sir_heap_context,
                    PLUS_64(sir_heap_context_ptr_low, 0bv64)) == heap_ptr_low;
modifies heap, heap_base, freep, sir_heap_context;
{
  var p, p_ptr: header_ptr_t;
  var prevp: header_ptr_t;
  var return_flag : bool;
  var nunits: uint64_t;
  var p_size: uint64_t;

  if (GT_64(size, heap_size)) { result := heap_failure; region := NULL; return; }
  if (size == 0bv64) { result := heap_success; region := NULL; return; }

  //uint64_t nunits = (nbytes + sizeof(malloc_header_t) - 1) / sizeof(malloc_header_t) + 1;
  nunits := PLUS_64(RSHIFT_64(MINUS_64(PLUS_64(size, 16bv64), 1bv64), 4bv64), 1bv64);
  assert GT_64(nunits, 0bv64);

  prevp := freep;
  if (prevp == NULL)
  {
    prevp := heap_base_ptr_low;
    freep := prevp;
    heap_base := STORE_LE_64(heap_base,
                             PLUS_64(heap_base_ptr_low, 0bv64),
                             freep);
    heap_base := STORE_LE_64(heap_base,
                             PLUS_64(heap_base_ptr_low, 8bv64),
                             freep);
  }

  p := LOAD_LE_64(heap, PLUS_64(prevp,0bv64));
  return_flag := false;

  while(!return_flag)
  invariant AddrInHeapInclusive(LOAD_LE_64(sir_heap_context, PLUS_64(sir_heap_context_ptr_low, 16bv64)));
  invariant LOAD_LE_64(sir_heap_context,
                      PLUS_64(sir_heap_context_ptr_low, 8bv64)) == heap_size;
  invariant LOAD_LE_64(sir_heap_context,
                      PLUS_64(sir_heap_context_ptr_low, 0bv64)) == heap_ptr_low;
  {
    p_ptr  := LOAD_LE_64(heap, PLUS_64(p, 0bv64)); //p->s.ptr
    p_size := LOAD_LE_64(heap, PLUS_64(p, 8bv64)); //p->s.size
    if (GE_64(p_size, nunits)) {
      if (p_size == nunits) {
        //prevp->s.ptr = p->s.ptr;
        //assert AddrInHeap(PLUS_64(prevp, 0bv64));
        heap := STORE_LE_64(heap, PLUS_64(prevp, 0bv64), p_ptr);
      } else {
        //assert AddrInHeap(PLUS_64(p, 8bv64));
        heap := STORE_LE_64(heap, PLUS_64(p, 8bv64), MINUS_64(p_size,nunits));
        p := PLUS_64(p, MINUS_64(p_size,nunits));
        //assert AddrInHeap(PLUS_64(p, 8bv64));
        heap := STORE_LE_64(heap, PLUS_64(p, 8bv64), nunits);
      }

      freep := prevp;
      region := PLUS_64(p, 16bv64); result := heap_success;
      return_flag := true;
    }

    if (p == freep) {
      call p := morecore(nunits);
      if (p == NULL) {
        region := NULL; result := heap_failure;
        return_flag := true;
      }
    }
    prevp := p;
    p := p_ptr;
  }
  return;
}
/*
procedure L_free( ap: uint8_ptr_t )
returns (result: heap_api_result_t)
modifies heap, freep;
{
  var bp, bp_ptr: header_ptr_t;
  var p, p_ptr : header_ptr_t;
  var p_size, bp_size: bv64;
  var break_flag : bool;

  bp := MINUS_64(ap, 16bv64);
  p := freep;
  break_flag := false;

  while (!break_flag && !( GT_64(bp,p) && LT_64(bp, p_ptr) ))
  //invariant AddrInHeapInclusive(LOAD_LE_64(sir_heap_context, PLUS_64(sir_heap_context_ptr_low, 16bv64)));
  //invariant LOAD_LE_64(sir_heap_context,
  //                    PLUS_64(sir_heap_context_ptr_low, 8bv64)) == heap_size;
  //invariant LOAD_LE_64(sir_heap_context,
  //                    PLUS_64(sir_heap_context_ptr_low, 0bv64)) == heap_ptr_low;
  {
    p_ptr := LOAD_LE_64(heap, PLUS_64(p, 0bv64)); //p->s.ptr
    if (GE_64(p,p_ptr) && (GT_64(bp,p) || LT_64(bp, p_ptr)))
    {
      break_flag := true;
    }

    p := p_ptr; //for(..; p = p->s.ptr)
  }

  p_ptr  := LOAD_LE_64(heap, PLUS_64(p, 0bv64)); //p->s.ptr
  p_size := LOAD_LE_64(heap, PLUS_64(p, 8bv64)); //p->s.size
  bp_ptr  := LOAD_LE_64(heap, PLUS_64(bp, 0bv64)); //p->s.ptr
  bp_size := LOAD_LE_64(heap, PLUS_64(bp, 8bv64)); //p->s.size

  if (PLUS_64(bp, bp_size) == p_ptr) {
    heap := STORE_LE_64(heap,
                        PLUS_64(bp, 8bv64),
                        PLUS_64(bp_size, LOAD_LE_64(heap, PLUS_64(p_ptr, 8bv64))));
    heap := STORE_LE_64(heap,
                        PLUS_64(bp, 0bv64),
                        LOAD_LE_64(heap, PLUS_64(p_ptr, 0bv64)));
  } else {
    heap := STORE_LE_64(heap,
                        PLUS_64(bp, 0bv64),
                        p_ptr);
  }

  if (PLUS_64(p, p_size) == bp_ptr) {
    heap := STORE_LE_64(heap,
                        PLUS_64(p, 8bv64),
                        PLUS_64(p_size, LOAD_LE_64(heap, PLUS_64(bp_ptr, 8bv64))));
    heap := STORE_LE_64(heap,
                        PLUS_64(p, 0bv64),
                        LOAD_LE_64(heap, PLUS_64(bp_ptr, 0bv64)));
  } else {
    heap := STORE_LE_64(heap,
                        PLUS_64(p, 0bv64),
                        bp);
  }

  freep := p;
}
*/
