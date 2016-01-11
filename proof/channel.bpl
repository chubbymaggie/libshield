/**
 * Implements send and recv API
 * Channel state from 0x1000 to 0x2000
 */

/*
typedef struct {
  uint8_t *send_buf_start;     // starting address of channel buffer
  uint64_t send_buf_size;      // size of channel buffer
  uint8_t *send_buf_current;   // current pointer in the channel buffer
  uint8_t *recv_buf_start;     // starting address of channel buffer
  uint64_t recv_buf_size;      // size of channel buffer
  uint8_t *recv_buf_current;   // current pointer in the channel buffer
  uint8_t* symmetric_key;      // secret 256-bit key for AES-GCM
} sir_channel_context_t;
*/

type channel_api_result_t;
const unique channel_success: channel_api_result_t;
const unique channel_failure: channel_api_result_t;

type{:datatype} sir_channel_context_t;
function{:constructor} sir_channel_context_t( send_buf_start: uint8_ptr_t,
                                              send_buf_size: uint64_t,
                                              send_buf_current: uint8_ptr_t,
                                              recv_buf_start: uint8_ptr_t,
                                              recv_buf_size: uint64_t,
                                              recv_buf_current: uint8_ptr_t,
                                              symmetric_key: uint64_t ) :
                       sir_channel_context_t;

procedure {:inline 1} write_channel_context(ctx: sir_channel_context_t)
modifies sir_channel_context;
{
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 0bv64),
                                     send_buf_start#sir_channel_context_t(ctx));
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 8bv64),
                                     send_buf_size#sir_channel_context_t(ctx));
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 16bv64),
                                     send_buf_current#sir_channel_context_t(ctx));
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 24bv64),
                                     recv_buf_start#sir_channel_context_t(ctx));
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 32bv64),
                                     recv_buf_size#sir_channel_context_t(ctx));
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 40bv64),
                                     recv_buf_current#sir_channel_context_t(ctx));
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 48bv64),
                                     symmetric_key#sir_channel_context_t(ctx));
}

/*
typedef struct {
 uint64_t message_type;
 uint64_t message_size;
} sir_message_header_t;
*/
type{:datatype} sir_message_header_t;
function{:constructor} sir_message_header_t (message_type: uint64_t,
                                             message_size: uint64_t) :
                       sir_message_header_t;

procedure {:inline 1} write_message_header(ptr: uint8_ptr_t,
                                           hdr: sir_message_header_t)
modifies send_buf;
{
  assert AddrInSendBuf(ptr) && AddrInSendBuf(PLUS_64(ptr, 15bv64));

  send_buf := STORE_LE_64(send_buf,
                          PLUS_64(ptr, 0bv64),
                          message_type#sir_message_header_t(hdr));
  send_buf := STORE_LE_64(send_buf,
                          PLUS_64(ptr, 8bv64),
                          message_size#sir_message_header_t(hdr));
}

procedure {:inline 1} init_channel( send_buf_start: uint8_ptr_t,
                                    send_buf_size: uint64_t,
                                    recv_buf_start: uint8_ptr_t,
                                    recv_buf_size: uint64_t,
                                    symmetric_key: uint64_t )
modifies sir_channel_context;
{
  var tmp: sir_channel_context_t;
  tmp  :=  sir_channel_context_t(send_buf_start,
                                 send_buf_size,
                                 send_buf_start,
                                 recv_buf_start,
                                 recv_buf_size,
                                 recv_buf_start,
                                 symmetric_key);
  call write_channel_context(tmp);
}

procedure {:inline 1} bytes_available_in_send_buf (size: uint64_t)
returns (result: bool)
requires AddrInSendBuf(LOAD_LE_64(sir_channel_context,
                                  PLUS_64(sir_channel_context_ptr_low, 16bv64)));
//requires LOAD_LE_64(sir_channel_context,
//                    PLUS_64(sir_channel_context_ptr_low, 8bv64)) == send_buf_size;
//requires LOAD_LE_64(sir_channel_context,
//                    PLUS_64(sir_channel_context_ptr_low, 0bv64)) == send_buf_ptr_low;
{
  var send_buf_current: uint8_ptr_t;
  var send_buf_size: uint8_ptr_t;
  var send_buf_start: uint8_ptr_t;

  send_buf_start   := LOAD_LE_64(sir_channel_context,
                                 PLUS_64(sir_channel_context_ptr_low, 0bv64));
  send_buf_size    := LOAD_LE_64(sir_channel_context,
                                 PLUS_64(sir_channel_context_ptr_low, 8bv64));
  send_buf_current := LOAD_LE_64(sir_channel_context,
                                 PLUS_64(sir_channel_context_ptr_low, 16bv64));

  result := LE_64(PLUS_64(send_buf_current, size), PLUS_64(send_buf_start, send_buf_size)) &&
            GE_64(PLUS_64(send_buf_current, size), send_buf_current);
  assert result ==>
         (AddrInSendBuf(send_buf_current) &&
          AddrInSendBuf(PLUS_64(send_buf_current, MINUS_64(size,1bv64))));
}

procedure {:inline 1} channel_send( msg_typ : uint64_t,
                                    msg_buf : uint8_ptr_t,
                                    msg_size: uint64_t )
returns (result: channel_api_result_t)
requires LE_64(msg_size, 160bv64);
requires AddrInSendBuf(LOAD_LE_64(sir_channel_context,
                                  PLUS_64(sir_channel_context_ptr_low, 16bv64)));
//ensures AddrInSendBuf(LOAD_LE_64(sir_channel_context,
//                                  PLUS_64(sir_channel_context_ptr_low, 16bv64)));

modifies send_buf, stack, sir_channel_context;
{
  var msg_header: sir_message_header_t; //ghost_var
  var send_buf_current: uint8_ptr_t;    //ghost_var
  var send_buf_size: uint8_ptr_t;    //ghost_var
  var send_buf_start: uint8_ptr_t;    //ghost_var
  var space_available : bool; //ghost var

  var msg_header_base_ptr: uint8_ptr_t;
  var rsp: bv64;

  //rsp is arbitrary at the time of call.
  havoc rsp; assume AddrInStack(rsp);
  //sir_message_header_t msg_header; resides on the stack
  rsp := MINUS_64(rsp, 16bv64);
  msg_header_base_ptr := rsp;
  //msg_header.message_type = type; msg_header.message_size = size;
  stack := STORE_LE_64(stack, PLUS_64(msg_header_base_ptr, 0bv64), msg_typ);
  stack := STORE_LE_64(stack, PLUS_64(msg_header_base_ptr, 8bv64), msg_size);

  //compute ghost vars
  send_buf_current := LOAD_LE_64(sir_channel_context,
                                 PLUS_64(sir_channel_context_ptr_low, 16bv64));

  //  if (!bytes_available_in_send_buf(size + sizeof(sir_message_header_t))) {
  //    return CHANNEL_FAILURE;
  //  }
  call space_available := bytes_available_in_send_buf(PLUS_64(msg_size, 16bv64));
  if (!space_available) {
    result := channel_failure; return;
  }


  msg_header := sir_message_header_t(msg_typ, msg_size);

  assume AddrInSendBuf(send_buf_current) &&
         AddrInSendBuf(PLUS_64(send_buf_current, PLUS_64(msg_size,15bv64))) &&
         LE_64(send_buf_current, PLUS_64(send_buf_current, PLUS_64(msg_size,16bv64)));

  //memcpy(sir_channel_context.send_buf_current, &msg_header, sizeof(msg_header));
  call write_message_header(send_buf_current, msg_header);
  //sir_channel_context.send_buf_current += sizeof(msg_header);
  send_buf_current := PLUS_64(send_buf_current, 16bv64); //sizeof(msg_header_t) = 16
  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 16bv64),
                                     send_buf_current); //sizeof(msg_header_t) = 16

  assume AddrInSendBuf(send_buf_current) &&
         AddrInSendBuf(PLUS_64(send_buf_current, MINUS_64(msg_size,1bv64))) &&
         LE_64(send_buf_current, PLUS_64(send_buf_current, MINUS_64(msg_size,1bv64)));

  //memcpy(sir_channel_context.send_buf_current, buf, size);
  call send_buf_memcpy(send_buf_current, msg_buf, msg_size);
  //sir_channel_context.send_buf_current += size;
  send_buf_current := PLUS_64(send_buf_current, msg_size);
  if (send_buf_ptr_high == send_buf_current)
  {
    send_buf_current := send_buf_ptr_low;
  }

  sir_channel_context := STORE_LE_64(sir_channel_context,
                                     PLUS_64(sir_channel_context_ptr_low, 16bv64),
                                     send_buf_current); //sizeof(msg_header_t)

  //yield: adversary havocs non-SIR memory
  //call havoc_non_sir_region(); //registers are preserved

  //return CHANNEL_SUCCESS;
  result := channel_success; return;
}

procedure L_send( msg_buf: uint8_ptr_t, msg_size: uint64_t )
returns (result: channel_api_result_t)
requires AddrInSendBuf(LOAD_LE_64(sir_channel_context, PLUS_64(sir_channel_context_ptr_low, 16bv64)));
requires LOAD_LE_64(sir_channel_context,
                     PLUS_64(sir_channel_context_ptr_low, 8bv64)) == send_buf_size;
requires LOAD_LE_64(sir_channel_context,
                     PLUS_64(sir_channel_context_ptr_low, 0bv64)) == send_buf_ptr_low;
ensures  AddrInSendBuf(LOAD_LE_64(sir_channel_context, PLUS_64(sir_channel_context_ptr_low, 16bv64)));
ensures LOAD_LE_64(sir_channel_context,
                     PLUS_64(sir_channel_context_ptr_low, 8bv64)) == send_buf_size;
ensures LOAD_LE_64(sir_channel_context,
                     PLUS_64(sir_channel_context_ptr_low, 0bv64)) == send_buf_ptr_low;
modifies send_buf, stack, sir_channel_context;
{
  var symmetric_key_ptr:  uint8_ptr_t; //ghost var

  var buf_128_bytes_ptr: uint8_ptr_t;
  var ciphertext_ptr: uint8_ptr_t;
  var rsp: bv64;

  //rsp is arbitrary at the time of call.
  havoc rsp; assume AddrInStack(rsp);
  rsp := MINUS_64(rsp, 288bv64);
  //uint8_t buf_128_bytes[128]; resides on the stack
  buf_128_bytes_ptr := PLUS_64(rsp,160bv64);
  //uint8_t ciphertext[160]; resides on the stack
  ciphertext_ptr := rsp;

  //TODO: fix this in the code
  if (! (AddrInU(msg_buf) &&
         AddrInU(PLUS_64(msg_buf,MINUS_64(msg_size,1bv64))) &&
         LE_64(msg_buf, PLUS_64(msg_buf,msg_size))) )
  {
    result := channel_failure;
    return;
  }

  //    if (size > 128) { return CHANNEL_FAILURE; }
  if (GT_64(msg_size, 128bv64)) {
    result := channel_failure;
    return;
  }

  // if (sir_channel_context.symmetric_key == NULL) {
  //   return channel_send(SEND_MESSAGE, buf, size);
  // }
  symmetric_key_ptr := LOAD_LE_64(sir_channel_context,
                                  PLUS_64(sir_channel_context_ptr_low, 64bv64));
  if (symmetric_key_ptr == NULL) {
    call result := channel_send(0bv64, msg_buf, msg_size);
    return;
  }

  // memset(buf_128_bytes, 0x00, sizeof(buf_128_bytes));
  call stack_memset(buf_128_bytes_ptr, 0bv8, 128bv64);
  // memcpy(buf_128_bytes, buf, size);
  call stack_memcpy(buf_128_bytes_ptr, msg_buf, msg_size);

  //rng_result = rdrand_get_bytes(16, ciphertext + 128);
  //if (rng_result != DRNG_SUCCESS) { exit(1); }
  call havoc_stack_region(PLUS_64(ciphertext_ptr, 128bv64), 16bv64);

  //aes_result = aes_gcm_encrypt_and_tag(..)
  call havoc_stack_region(ciphertext_ptr, 160bv64);

  //send_result = channel_send(SEND_ENCRYPTED_MESSAGE, ciphertext, 160);
  call result := channel_send(0bv64, ciphertext_ptr, 160bv64);

  return;
}

procedure L_recv( msg_buf: uint8_ptr_t, msg_size: uint64_t )
returns (result: channel_api_result_t)
{
  result := channel_failure;
}
