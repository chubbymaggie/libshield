procedure main()
modifies mem;
{
  var buf: uint8_ptr_t;
  var size: uint64_t;
  var channel_result : channel_api_result_t;

  call init_channel(send_buf_ptr_low, send_buf_size,
                    recv_buf_ptr_low, recv_buf_size,
                    symmetric_key_ptr_low);
                    
  while(*)
  invariant AddrInSendBuf(get_send_buf_current(mem));
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
