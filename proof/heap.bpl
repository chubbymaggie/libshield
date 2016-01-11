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

type{:datatype} sir_heap_context_t;
function{:constructor} sir_heap_context_t( heap_buf_start: uint8_ptr_t,
                                           heap_buf_size: uint64_t,
                                           heap_buf_current: uint8_ptr_t ) :
                       sir_heap_context_t;

/*
typedef struct header {
    struct header *ptr; // next block if on free list
    uint64_t size;      // size of this block
} malloc_header_t;
*/
type{:datatype} malloc_header_t;
function{:constructor} malloc_header_t( ptr : header_ptr_t,
                                        size: uint64_t ) :
                       malloc_header_t;

procedure {:inline 1} write_heap_context(ctx: sir_heap_context_t)
modifies sir_heap_context;
{
  sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 0bv64),
                                    heap_buf_start#sir_heap_context_t(ctx));
  sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 8bv64),
                                    heap_buf_size#sir_heap_context_t(ctx));
  sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 16bv64),
                                    heap_buf_current#sir_heap_context_t(ctx));
}

procedure {:inline 1} init_heap ( heap_buf_start: uint8_ptr_t,
                                  heap_buf_size: uint64_t )
modifies sir_heap_context, freep;
{
  var tmp: sir_heap_context_t;
  tmp  :=  sir_heap_context_t ( heap_buf_start,
                                heap_buf_size,
                                heap_buf_start);
  call write_heap_context(tmp);
  freep := NULL;
}

procedure {:inline 1} bytes_available_in_heap_buf (size: uint64_t)
returns (result: bool)
requires AddrInHeap(LOAD_LE_64(sir_heap_context,
                               PLUS_64(sir_heap_context_ptr_low, 16bv64)));
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

  result := LE_64(PLUS_64(heap_buf_current, size), PLUS_64(heap_buf_start, heap_buf_size)) &&
            GE_64(PLUS_64(heap_buf_current, size), heap_buf_current);
  assert result ==>
         (AddrInHeap(heap_buf_current) &&
          AddrInHeap(PLUS_64(heap_buf_current, MINUS_64(size,1bv64))));
}

procedure {:inline 1} morecore( nunits: uint64_t )
returns (result: header_ptr_t)
modifies heap, sir_heap_context, freep;
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
    heap := STORE_LE_64(heap, PLUS_64(result, 8bv64), nunits);
    call free_api_result := L_free(PLUS_64(result, 8bv64));
    sir_heap_context := STORE_LE_64(sir_heap_context,
                                    PLUS_64(sir_heap_context_ptr_low, 16bv64),
                                    nbytes);
  }
  else { result := NULL; return; }
}

procedure L_malloc( size: uint64_t )
returns (result: heap_api_result_t, region: virtual_addr_t)
modifies heap, heap_base, freep, sir_heap_context;
{
  var p, p_ptr: header_ptr_t;
  var prevp: header_ptr_t;
  var return_flag : bool;
  var nunits: uint64_t;
  var p_size: uint64_t;

  nunits := RSHIFT_64(nunits, 4bv64);

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

  while(!return_flag) {
    p_ptr  := LOAD_LE_64(heap, PLUS_64(p, 0bv64)); //p->s.ptr
    p_size := LOAD_LE_64(heap, PLUS_64(p, 8bv64)); //p->s.size
    if (GE_64(p_size, nunits)) {
      if (p_size == nunits) {
        //prevp->s.ptr = p->s.ptr;
        heap := STORE_LE_64(heap, PLUS_64(prevp, 0bv64), p_ptr);
      } else {
        heap := STORE_LE_64(heap, PLUS_64(p, 8bv64), MINUS_64(p_size,nunits));
        p := PLUS_64(p, MINUS_64(p_size,nunits));
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
