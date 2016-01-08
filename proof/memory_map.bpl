var mem: mem_t;

const NULL: uint8_ptr_t; axiom NULL == 0bv64;

/*
static sir_channel_context_t sir_channel_context;
*/
const static_sir_channel_context_base_ptr : uint8_ptr_t;
axiom static_sir_channel_context_base_ptr == 40960bv64;

const stack_ptr_low: uint8_ptr_t;
axiom stack_ptr_low == 4096bv64;

const stack_ptr_high: uint8_ptr_t;
axiom stack_ptr_high == 8192bv64;

function {:inline} AddrInStack(rsp: bv64): bool
{
  GE_64(rsp, stack_ptr_low) && LT_64(rsp, stack_ptr_high)
}

const stack_guard_ptr_low: uint8_ptr_t;
axiom stack_guard_ptr_low == 8192bv64;

const stack_guard_ptr_high: uint8_ptr_t;
axiom stack_guard_ptr_high == 12288bv64;

const send_buf_ptr_low: uint8_ptr_t;
axiom send_buf_ptr_low == 409600bv64;
const send_buf_size: uint64_t;
axiom send_buf_size == 4096bv64;

const recv_buf_ptr_low: uint8_ptr_t;
axiom recv_buf_ptr_low == 413696bv64;
const recv_buf_size: uint64_t;
axiom recv_buf_size == 4096bv64;

const symmetric_key_ptr_low: uint8_ptr_t;
axiom symmetric_key_ptr_low == 45056bv64;
