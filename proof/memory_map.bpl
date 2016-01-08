var mem: mem_t;

const NULL: uint8_ptr_t;
axiom NULL == 0bv64;

/*
static sir_channel_context_t sir_channel_context;
*/
const static_sir_channel_context_base_ptr : uint8_ptr_t;
axiom static_sir_channel_context_base_ptr == 40960bv64;

const stack_ptr_low: uint8_ptr_t;
axiom stack_ptr_low == 8192bv64;

const stack_ptr_high: uint8_ptr_t;
axiom stack_ptr_high == 12288bv64;

function {:inline} AddrInStack(rsp: bv64): bool
{
  GE_64(rsp, stack_ptr_low) && LT_64(rsp, stack_ptr_high)
}

const stack_guard_ptr_low: uint8_ptr_t;
axiom stack_guard_ptr_low == 4096bv64;

const stack_guard_ptr_high: uint8_ptr_t;
axiom stack_guard_ptr_high == 8192bv64;

const send_buf_ptr_low: uint8_ptr_t;
axiom send_buf_ptr_low == 417792bv64;
const send_buf_size: uint64_t;
axiom send_buf_size == 4096bv64;

const recv_buf_ptr_low: uint8_ptr_t;
axiom recv_buf_ptr_low == 413696bv64;
const recv_buf_size: uint64_t;
axiom recv_buf_size == 4096bv64;

const symmetric_key_ptr_low: uint8_ptr_t;
axiom symmetric_key_ptr_low == 45056bv64;

const U_ptr_low: uint8_ptr_t;
axiom U_ptr_low == 368640bv64;
const U_ptr_high : uint8_ptr_t;
axiom U_ptr_high == 409600bv64;

const SIR_ptr_low: uint8_ptr_t;
axiom SIR_ptr_low == 0bv64;
const SIR_ptr_high : uint8_ptr_t;
axiom SIR_ptr_high == 409600bv64;

function {:inline} AddrInU(ptr: bv64): bool
{
  GE_64(ptr, U_ptr_low) && LT_64(ptr, U_ptr_high)
}

function {:inline} AddrInSIR(ptr: bv64): bool
{
  GE_64(ptr, SIR_ptr_low) && LT_64(ptr, SIR_ptr_high)
}

function {:inline} get_send_buf_current(mem: mem_t): uint8_ptr_t
{
  LOAD_LE_64(mem, PLUS_64(static_sir_channel_context_base_ptr, 16bv64))
}

function {:inline} AddrInSendBuf(ptr: bv64): bool
{
  GE_64(ptr, send_buf_ptr_low) && LT_64(ptr, PLUS_64(send_buf_ptr_low, send_buf_size))
}
