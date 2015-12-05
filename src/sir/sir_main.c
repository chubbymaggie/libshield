#include <string.h>
#include <stdint.h>
#include "rand/drng.h"
#include "sir_dhm.h"

static uint8_t * send_buf;
static uint8_t * recv_buf;
static uint8_t * stack_buf;
static uint8_t * heap_buf;

extern void mbedtls_memory_buffer_alloc_init( unsigned char *buf, size_t len );
extern void mbedtls_memory_buffer_alloc_free();


void exit(int status)
{
  (void) status; //to supress unused parameter warning
  __asm("int3");
  while(1) { }
}

void L_main() 
{
  char *hello = "Hello World!";
  uint8_t iv[16];
  int r;
  uint8_t remote_public[1000];
  dhm_compute_secret_ret_t return_value;

  /* recv remote's DHM public key */
  //memcpy(remote_public, recv_buf, 1000);
  //return_value = dhm_compute_secret(remote_public);
  //if (return_value.outcome == FAILURE) { exit(1); }

  /* output some junk */
  memset(iv, 0, 16);
  r = rdrand_get_bytes(16, iv);
  if (r != DRNG_SUCCESS) { exit(1); }

  memcpy(send_buf, hello, strlen(hello) + 1); 
  memset(send_buf + strlen(hello) + 1, 1, sizeof(uint8_t));
  memcpy(send_buf + strlen(hello) + 1 + sizeof(uint8_t), iv, 16);
  memcpy(send_buf + strlen(hello) + 1 + sizeof(uint8_t) + 16, &return_value.dhm_sec_size, sizeof(uint64_t));  
  memcpy(send_buf + strlen(hello) + 1 + sizeof(uint8_t) + 16 + sizeof(uint64_t), return_value.dhm_sec, return_value.dhm_sec_size);  
}

void sir_main() 
{
  /* stack switching */
  uint64_t old_rsp, new_rsp;
  new_rsp = (uint64_t) stack_buf;
  __asm("movq %%rsp, %0":"=r"(old_rsp)::);
  __asm("movq %0, %%rsp"::"r"(new_rsp):);

  L_main();
  mbedtls_memory_buffer_alloc_free( );

  /* reset the stack */
  __asm("movq %0, %%rsp"::"r"(old_rsp):);
}

void L_init() 
{
  dhm_make_public_params_ret_t return_value = dhm_make_public_params();
  if (return_value.outcome == FAILURE) { exit(1); }
  memcpy(send_buf, return_value.dhm_pub, 1000);
}

void sir_init(uint8_t *stack, uint8_t *heap, uint8_t *recv, uint8_t *send) 
{
  uint64_t old_rsp, new_rsp;
  new_rsp = (uint64_t) stack + 1048568;
  __asm("movq %%rsp, %0":"=r"(old_rsp)::);
  __asm("movq %0, %%rsp"::"r"(new_rsp):);

  send_buf = send;
  recv_buf = recv;
  stack_buf = (uint8_t *) new_rsp;
  heap_buf = (uint8_t *) heap;
  mbedtls_memory_buffer_alloc_init( heap, 1048576 );
  L_init();

  __asm("movq %0, %%rsp"::"r"(old_rsp):);
}
