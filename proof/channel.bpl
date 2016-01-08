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
modifies mem;
{
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 0bv64),
                          send_buf_start#sir_channel_context_t(ctx));
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 8bv64),
                          send_buf_size#sir_channel_context_t(ctx));
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 16bv64),
                          send_buf_current#sir_channel_context_t(ctx));
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 24bv64),
                          recv_buf_start#sir_channel_context_t(ctx));
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 32bv64),
                          recv_buf_size#sir_channel_context_t(ctx));
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 40bv64),
                          recv_buf_current#sir_channel_context_t(ctx));
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 48bv64),
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
modifies mem;
{
  mem := STORE_LE_64(mem, PLUS_64(ptr, 0bv64),
                         message_type#sir_message_header_t(hdr));
  mem := STORE_LE_64(mem, PLUS_64(ptr, 8bv64),
                         message_size#sir_message_header_t(hdr));
}

procedure {:inline 1} init_channel( send_buf_start: uint8_ptr_t,
                                    send_buf_size: uint64_t,
                                    recv_buf_start: uint8_ptr_t,
                                    recv_buf_size: uint64_t,
                                    symmetric_key: uint64_t )
modifies mem;
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
{
  var send_buf_current: uint8_ptr_t;
  var send_buf_size: uint8_ptr_t;
  var send_buf_start: uint8_ptr_t;

  send_buf_start   := LOAD_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 0bv64));
  send_buf_size    := LOAD_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 8bv64));
  send_buf_current := LOAD_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 16bv64));

  result := LT_64(PLUS_64(send_buf_current, size), PLUS_64(send_buf_start, send_buf_size)) &&
            GE_64(PLUS_64(send_buf_current, size), send_buf_current);
}

procedure {:inline 1} channel_send( msg_typ: uint64_t,
                                    msg_buf: uint8_ptr_t,
                                    msg_size: uint64_t )
returns (result: channel_api_result_t)
modifies mem;
{
  var msg_header: sir_message_header_t; //ghost_var
  var send_buf_current: uint8_ptr_t;    //ghost_var
  var space_available : bool; //ghost var

  var msg_header_base_ptr: uint8_ptr_t;
  var rsp: bv64;

  //rsp is arbitrary at the time of call.
  havoc rsp; assume AddrInStack(rsp);
  //sir_message_header_t msg_header; resides on the stack
  msg_header_base_ptr := rsp;
  //msg_header.message_type = type; msg_header.message_size = size;
  call havoc_region(msg_header_base_ptr, 16bv64);

  //  if (!bytes_available_in_send_buf(size + sizeof(sir_message_header_t))) {
  //    return CHANNEL_FAILURE;
  //  }
  call space_available := bytes_available_in_send_buf(PLUS_64(msg_size, 16bv64));
  if (!space_available) {
    result := channel_failure; return;
  }

  //compute ghost vars
  send_buf_current := LOAD_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 16bv64));
  msg_header := sir_message_header_t(msg_typ, msg_size);

  //memcpy(sir_channel_context.send_buf_current, &msg_header, sizeof(msg_header));
  call write_message_header(send_buf_current, msg_header);
  //sir_channel_context.send_buf_current += sizeof(msg_header);
  send_buf_current := PLUS_64(send_buf_current, 16bv64); //sizeof(msg_header_t) = 16
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 16bv64),
                          send_buf_current); //sizeof(msg_header_t) = 16

  //memcpy(sir_channel_context.send_buf_current, buf, size);
  call memcpy(send_buf_current, msg_buf, msg_size);
  //sir_channel_context.send_buf_current += size;
  send_buf_current := PLUS_64(send_buf_current, msg_size);
  mem := STORE_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 16bv64),
                          send_buf_current); //sizeof(msg_header_t)

  //yield: adversary havocs non-SIR memory
  //call havoc_non_sir_region(); //registers are preserved

  //return CHANNEL_SUCCESS;
  result := channel_success; return;
}

procedure L_send( msg_buf: uint8_ptr_t, msg_size: uint64_t )
//returns (result: channel_api_result_t)
modifies mem;
{
  var rsp: bv64;
  var symmetric_key: uint8_ptr_t;
  var result: channel_api_result_t;

  //rsp is arbitrary at the time of call.
  havoc rsp; assume AddrInStack(rsp);

  if (GT_64(msg_size, 128bv64)) {
    //result := channel_failure;
    return;
  }

  symmetric_key := LOAD_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 64bv64));
  if (symmetric_key == NULL) {
    call result := channel_send(0bv64, msg_buf, msg_size);
    return;
  }

  //result := channel_success;
  return;
}

procedure L_recv( msg_buf: uint8_ptr_t, msg_size: uint64_t )
//returns (result: channel_api_result_t)
modifies mem;
{

}
