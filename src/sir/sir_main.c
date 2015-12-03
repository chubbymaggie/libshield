#include <string.h>
#include <stdint.h>
#include "crypto_params.h"
#include "drng/drng.h"

//static unsigned char buf[16777216];
//unsigned char buf[1048576] __attribute__ ((section (".crypto_heap")));
unsigned char buf[1048576];

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

int sir_main(uint8_t *stack, uint8_t *heap, uint8_t *recv_buf, uint8_t *send_buf) 
{
  uint64_t old_rsp, new_rsp;
  new_rsp = stack + 1048568;
  __asm("movq %%rsp, %0":"=r"(old_rsp)::);
  __asm("movq %0, %%rsp"::"r"(new_rsp):);

  L_main(stack, heap, recv_buf, send_buf);

  __asm("movq %0, %%rsp"::"r"(old_rsp):);
}

int L_main(uint8_t *stack, uint8_t *heap, uint8_t *recv_buf, uint8_t *send_buf) 
{
  result_t result;
  char *input_P = DHM_P;
  char *input_G = DHM_G;
  mbedtls_memory_buffer_alloc_init( heap, 1048576 );
  result = test_suite_dhm_do_dhm(16, input_P, 16, input_G);
  if (result == FAILURE) { exit(1); }
  mbedtls_memory_buffer_alloc_free( );
  char *hello = "Hello World!";
  memcpy(send_buf, hello, strlen(hello)); 
  unsigned char iv[16];
  memset(iv, 0, 16);
  int r = rdrand_get_bytes(16, iv);
  if (r == DRNG_SUCCESS) {
    memset(send_buf + strlen(hello) + 1, 1, sizeof(char));
    memcpy(send_buf + strlen(hello) + 1 + sizeof(char), iv, 16);
  }
  else {
    memcpy(send_buf + strlen(hello) + 1, 0, sizeof(int));
  }
  return result;
}
