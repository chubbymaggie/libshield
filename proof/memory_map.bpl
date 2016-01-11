const NULL: uint8_ptr_t;              axiom NULL == 0bv64;

var send_buf: mem_t; //from 417792bv64 to 421888bv64
const send_buf_size: uint64_t;        axiom send_buf_size == 4096bv64;
const send_buf_ptr_low: uint8_ptr_t;  axiom send_buf_ptr_low == 417792bv64;
const send_buf_ptr_high: uint8_ptr_t; axiom send_buf_ptr_high == 421888bv64;
function {:inline} AddrInSendBuf(ptr: bv64): bool { GE_64(ptr, send_buf_ptr_low) && LT_64(ptr, send_buf_ptr_high) }

var recv_buf: mem_t; //from 413696bv64 to 417792bv64
const recv_buf_size: uint64_t;        axiom recv_buf_size == 4096bv64;
const recv_buf_ptr_low: uint8_ptr_t;  axiom recv_buf_ptr_low == 413696bv64;
const recv_buf_ptr_high: uint64_t;    axiom recv_buf_ptr_high == 417792bv64;
function {:inline} AddrInRecvBuf(ptr: bv64): bool { GE_64(ptr, recv_buf_ptr_low) && LT_64(ptr, recv_buf_ptr_high) }

/*************** SIR ****************/
const SIR_ptr_high : uint8_ptr_t;     axiom SIR_ptr_high == 409600bv64;

var U: mem_t; //from 368640bv64 to 409600bv64
const U_ptr_low : uint8_ptr_t;        axiom U_ptr_low == 368640bv64;
const U_ptr_high : uint8_ptr_t;       axiom U_ptr_high == 409600bv64;
function {:inline} AddrInU(ptr: bv64): bool { GE_64(ptr, U_ptr_low) && LT_64(ptr, U_ptr_high) }

/*************** lot of empty space ****************/
var sir_heap_context: mem_t; //40960bv64 to 41016bv64
const sir_heap_context_ptr_low : uint8_ptr_t;  axiom sir_heap_context_ptr_low == 49152bv64;
const sir_heap_context_ptr_high : uint8_ptr_t; axiom sir_heap_context_ptr_high == 49176bv64;


var symmetric_key: mem_t; //from 45056bv64 to 45088bv64
const symmetric_key_ptr_low: uint8_ptr_t;                axiom symmetric_key_ptr_low == 45056bv64;
const symmetric_key_ptr_high: uint8_ptr_t;               axiom symmetric_key_ptr_high == 45088bv64;

var sir_channel_context: mem_t; //40960bv64 to 41016bv64
const sir_channel_context_ptr_low : uint8_ptr_t;  axiom sir_channel_context_ptr_low == 40960bv64;
const sir_channel_context_ptr_high : uint8_ptr_t; axiom sir_channel_context_ptr_high == 41016bv64;

/*************** lot of empty space ****************/
var heap_base: mem_t;
const heap_base_ptr_low: uint8_ptr_t;        axiom heap_ptr_low == 16384bv64;
const heap_base_ptr_high: uint8_ptr_t;       axiom heap_ptr_high == 16400bv64;

var freep: header_ptr_t; //TODO: put this in memory

var heap: mem_t; //from 12288bv64 to 16384bv64
const heap_ptr_low: uint8_ptr_t;        axiom heap_ptr_low == 12288bv64;
const heap_ptr_high: uint8_ptr_t;       axiom heap_ptr_high == 16384bv64;
function {:inline} AddrInHeap(x: bv64): bool { GE_64(x, heap_ptr_low) && LT_64(x, heap_ptr_high) }

var stack: mem_t; //from 8192bv64 to 12288bv64
const stack_ptr_low: uint8_ptr_t;        axiom stack_ptr_low == 8192bv64;
const stack_ptr_high: uint8_ptr_t;       axiom stack_ptr_high == 12288bv64;
function {:inline} AddrInStack(rsp: bv64): bool { GE_64(rsp, stack_ptr_low) && LT_64(rsp, stack_ptr_high) }

var stack_guard: mem_t; //from 4096bv64 to 8192bv64
const stack_guard_ptr_low: uint8_ptr_t;  axiom stack_guard_ptr_low == 4096bv64;
const stack_guard_ptr_high: uint8_ptr_t; axiom stack_guard_ptr_high == 8192bv64;
function {:inline} AddrInStackGuard(rsp: bv64): bool { GE_64(rsp, stack_guard_ptr_low) && LT_64(rsp, stack_guard_ptr_high) }


const SIR_ptr_low: uint8_ptr_t;          axiom SIR_ptr_low == 4096bv64;
function {:inline} AddrInSIR(ptr: bv64): bool { GE_64(ptr, SIR_ptr_low) && LT_64(ptr, SIR_ptr_high) }

/*************** SIR ****************/
