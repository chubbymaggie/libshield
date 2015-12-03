#include <string.h>
#include <stdint.h>
#include "crypto_params.h"
#include "rand/drng.h"

static uint8_t * send_buf;
static uint8_t * recv_buf;

extern void mbedtls_memory_buffer_alloc_init( unsigned char *buf, size_t len );
extern void mbedtls_memory_buffer_alloc_free();

typedef enum {SUCCESS = 0, FAILURE = 1} result_t;
result_t test_suite_dhm_do_dhm( int radix_P, char *input_P,
                 int radix_G, char *input_G );

void exit(int status)
{
  (void) status; //to supress unused parameter warning
  __asm("int3");
  while(1) { }
}


int L_main() 
{
  result_t result;
  char *hello = "Hello World!";
  uint8_t iv[16];
  int r;
  char *input_P = DHM_P;
  char *input_G = DHM_G;
  result = test_suite_dhm_do_dhm(16, input_P, 16, input_G);
  if (result == FAILURE) { exit(1); }
  mbedtls_memory_buffer_alloc_free( );
  memcpy(send_buf, hello, strlen(hello)); 
  memset(iv, 0, 16);
  r = rdrand_get_bytes(16, iv);
  if (r == DRNG_SUCCESS) {
    memset(send_buf + strlen(hello) + 1, 1, sizeof(uint8_t));
    memcpy(send_buf + strlen(hello) + 1 + sizeof(uint8_t), iv, 16);
  }
  else {
    memset(send_buf + strlen(hello) + 1, 0, sizeof(uint8_t));
  }
  return result;
}

void sir_main(uint8_t *stack, uint8_t *heap, uint8_t *recv, uint8_t *send) 
{
  uint64_t old_rsp, new_rsp;
  new_rsp = (uint64_t) stack + 1048568;
  __asm("movq %%rsp, %0":"=r"(old_rsp)::);
  __asm("movq %0, %%rsp"::"r"(new_rsp):);

  send_buf = send;
  recv_buf = recv;
  mbedtls_memory_buffer_alloc_init( heap, 1048576 );
  L_main();

  __asm("movq %0, %%rsp"::"r"(old_rsp):);
}
