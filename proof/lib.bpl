procedure {:inline 1} send_buf_memcpy(dst: uint8_ptr_t, src: uint8_ptr_t, size: uint64_t)
modifies send_buf;
{
  assert LE_64(dst, PLUS_64(dst, size)) &&
         AddrInSendBuf(dst) &&
         AddrInSendBuf(PLUS_64(dst,MINUS_64(size, 1bv64)));
  call send_buf := memcpy(send_buf, dst, src, size);
}

procedure {:inline 1} stack_memcpy(dst: uint8_ptr_t, src: uint8_ptr_t, size: uint64_t)
modifies stack;
{
  assert LE_64(dst, PLUS_64(dst,size)) &&
         (AddrInStack(dst) || AddrInStackGuard(dst)) &&
         (AddrInStack(PLUS_64(dst,MINUS_64(size, 1bv64))) || AddrInStackGuard(PLUS_64(dst,MINUS_64(size, 1bv64))));
  call stack := memcpy(stack, dst, src, size);
}

procedure {:inline 1} memcpy(m: mem_t, dst: uint8_ptr_t, src: uint8_ptr_t, size: uint64_t)
returns (result: mem_t)
{
  assume (forall i : virtual_addr_t ::
    ((LT_64(i, dst) || GE_64(i, PLUS_64(dst,size))) ==>
    (result[i] == m[i])));
  assume (forall i : virtual_addr_t ::
    ((GE_64(i, dst) && LT_64(i, PLUS_64(dst,size))) ==>
    (result[i] == m[PLUS_64(src,MINUS_64(i,dst))])));
}

procedure {:inline 1} stack_memset(ptr: uint8_ptr_t, val: uint8_t, size: uint64_t)
modifies stack;
{
  assert LE_64(ptr, PLUS_64(ptr,size)) &&
         (AddrInStack(ptr) || AddrInStackGuard(ptr)) &&
         (AddrInStack(PLUS_64(ptr,MINUS_64(size, 1bv64))) || AddrInStackGuard(PLUS_64(ptr,MINUS_64(size, 1bv64))));
  call stack := memset(stack, ptr, val, size);
}

procedure {:inline 1} memset(m: mem_t, ptr: uint8_ptr_t, val: uint8_t, size: uint64_t)
returns (result: mem_t)
{
  assume (forall i : virtual_addr_t ::
    ((LT_64(i, ptr) || GE_64(i, PLUS_64(ptr,size))) ==>
    (result[i] == m[i])));
  assume (forall i : virtual_addr_t ::
    ((GE_64(i, ptr) && LT_64(i, PLUS_64(ptr,size))) ==>
    (result[i] == val)));
}

procedure {:inline 1} havoc_stack_region(ptr: uint8_ptr_t, size: uint64_t)
modifies stack;
{
  var old_stack: mem_t;

  assert LE_64(ptr, PLUS_64(ptr,size)) &&
         (AddrInStack(ptr) || AddrInStackGuard(ptr)) &&
         (AddrInStack(PLUS_64(ptr,MINUS_64(size, 1bv64))) || AddrInStackGuard(PLUS_64(ptr,MINUS_64(size, 1bv64))));
  old_stack := stack;
  havoc stack;
  assume (forall i : virtual_addr_t ::
    ((LT_64(i, ptr) || GE_64(i, PLUS_64(ptr,size))) ==>
    (old_stack[i] == stack[i])));
}
