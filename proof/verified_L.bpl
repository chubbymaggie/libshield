procedure main()
modifies send_buf, recv_buf, stack, stack_guard, sir_channel_context, symmetric_key, U;
{
  var buf: uint8_ptr_t;
  var size: uint64_t;
  var channel_result : channel_api_result_t;

  call init_channel(send_buf_ptr_low, send_buf_size,
                    recv_buf_ptr_low, recv_buf_size,
                    symmetric_key_ptr_low);

  while(*)
  invariant AddrInSendBuf(LOAD_LE_64(sir_channel_context, PLUS_64(sir_channel_context_ptr_low, 16bv64)));
  {
    havoc buf;
    havoc size;

    if (*) { call U(); }
    //else if (*) { call L_malloc(size); }
    //else if (*) { call L_free(buf); }
    else if (*) { call channel_result := L_send(buf,size); }
    //else if (*) { call channel_result := L_recv(buf,size); }
  }
}
