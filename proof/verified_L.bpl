procedure main()
modifies send_buf, recv_buf, stack, stack_guard, freep, sir_heap_context,
         sir_channel_context, symmetric_key, U, heap, heap_base;
{
  var buf: uint8_ptr_t;
  var size: uint64_t;
  var channel_result : channel_api_result_t;
  var heap_result : heap_api_result_t;
  var malloc_region : uint8_ptr_t;

  call init_channel(send_buf_ptr_low, send_buf_size,
                    recv_buf_ptr_low, recv_buf_size,
                    symmetric_key_ptr_low);
  call init_heap(heap_ptr_low, heap_size);

  while(*)
  invariant AddrInSendBuf(LOAD_LE_64(sir_channel_context, PLUS_64(sir_channel_context_ptr_low, 16bv64)));
  invariant LOAD_LE_64(sir_channel_context,
                       PLUS_64(sir_channel_context_ptr_low, 8bv64)) == send_buf_size;
  invariant LOAD_LE_64(sir_channel_context,
                       PLUS_64(sir_channel_context_ptr_low, 0bv64)) == send_buf_ptr_low;
  invariant AddrInHeapInclusive(LOAD_LE_64(sir_heap_context, PLUS_64(sir_heap_context_ptr_low, 16bv64)));
  invariant LOAD_LE_64(sir_heap_context,
                      PLUS_64(sir_heap_context_ptr_low, 8bv64)) == heap_size;
  invariant LOAD_LE_64(sir_heap_context,
                      PLUS_64(sir_heap_context_ptr_low, 0bv64)) == heap_ptr_low;
  {
    havoc buf;
    havoc size;

    if (*) { call U(); }
    else if (*) { call heap_result, malloc_region := L_malloc(size); }
    //else if (*) { call heap_result := L_free(buf); }
    else if (*) { call channel_result := L_send(buf,size); }
    //else if (*) { call channel_result := L_recv(buf,size); }
  }
}
