#include <string.h>
#include <stdint.h>
#include "rand/drng.h"
#include "sir_dhm.h"
#include "sir_aes_gcm.h"
#include "sir_channel.h"

static uint8_t * stack_buf;
static uint8_t * heap_buf;
static uint8_t * recv_buf;
static uint8_t * send_buf;
static uint64_t sir_rsp, host_rsp;

extern void mbedtls_memory_buffer_alloc_init( unsigned char *buf, size_t len );

void exit(int status)
{
  (void) status; //to supress unused parameter warning
  __asm("int3");
  while(1) { }
}

void yield()
{
  __asm("pushq %%rbp":::);
  __asm("pushq %%rbx":::);
  __asm("pushq %%r12":::);
  __asm("pushq %%r13":::);
  __asm("pushq %%r14":::);
  __asm("pushq %%r15":::);
  __asm("movq %%rsp, %0":"=r"(sir_rsp)::);
  __asm("movq %0, %%rsp"::"r"(host_rsp):);
  __asm("popq %%r15":::);
  __asm("popq %%r14":::);
  __asm("popq %%r13":::);
  __asm("popq %%r12":::);
  __asm("popq %%rbx":::);
  __asm("popq %%rbp":::);
}

void sir_entry() 
{
  __asm("pushq %%rbp":::);
  __asm("pushq %%rbx":::);
  __asm("pushq %%r12":::);
  __asm("pushq %%r13":::);
  __asm("pushq %%r14":::);
  __asm("pushq %%r15":::);
  __asm("movq %%rsp, %0":"=r"(host_rsp)::);
  __asm("movq %0, %%rsp"::"r"(sir_rsp):);
  __asm("popq %%r15":::);
  __asm("popq %%r14":::);
  __asm("popq %%r13":::);
  __asm("popq %%r12":::);
  __asm("popq %%rbx":::);
  __asm("popq %%rbp":::);
}

void L_main() 
{
  char *hello = "Hello World!";
  int rng_result;
  sir_dhm_context_t sir_dhm_context;
  uint8_t remote_ciphertext[160];
  uint8_t ciphertext[128];
  uint8_t tag[16];
  uint8_t iv[16];
  uint8_t random_bytes[16];
  uint8_t cleartext[128];
  uint8_t out_cleartext[128];
  channel_api_result_t send_result, recv_result;
  aes_gcm_api_result_t aes_result;
  dhm_api_result_t dhm_result;
  uint8_t constant_one = 1;
  size_t constant_384 = 384;

  channel_send_init(send_buf, 4096);
  channel_recv_init(recv_buf, 4096);
  mbedtls_memory_buffer_alloc_init( heap_buf, 1048576 );
  dhm_result = dhm_make_public_params(&sir_dhm_context);
  if (dhm_result == DHM_FAILURE) { exit(1); }
  send_result = channel_send(sir_dhm_context.public_component, 1000);
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  channel_send_reset();

  yield();

  /* recv remote's DHM public key */
  recv_result = channel_recv(sir_dhm_context.remote_component, 1000);
  if (recv_result == CHANNEL_FAILURE) { exit(1); }
  dhm_result = dhm_compute_secret(&sir_dhm_context);
  if (dhm_result == DHM_FAILURE) { exit(1); }

  /* output some junk */
  memset(iv, 0, 16);
  rng_result = rdrand_get_bytes(16, iv);
  if (rng_result != DRNG_SUCCESS) { exit(1); }
  rng_result = rdrand_get_bytes(16, random_bytes);
  if (rng_result != DRNG_SUCCESS) { exit(1); }

  send_result = channel_send((uint8_t *) hello, strlen(hello) + 1);
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  send_result = channel_send(&constant_one, sizeof(uint8_t));
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  send_result = channel_send(iv, 16);
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  send_result = channel_send(random_bytes, 16);
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  send_result = channel_send((uint8_t *) &constant_384, sizeof(uint64_t));  
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  send_result = channel_send(sir_dhm_context.secret_component, sizeof(sir_dhm_context.secret_component));  
  if (send_result == CHANNEL_FAILURE) { exit(1); }

  memcpy(cleartext, "pldi2016", strlen("pldi2016") + 1);
  aes_result = aes_gcm_encrypt_and_tag(sir_dhm_context.secret_component, cleartext, iv, tag, ciphertext);  
  if (aes_result == AES_GCM_FAILURE) { exit(1); }
  send_result = channel_send(ciphertext, sizeof(ciphertext));
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  send_result = channel_send(tag, sizeof(tag));
  if (send_result == CHANNEL_FAILURE) { exit(1); }
  send_result = channel_send(iv, sizeof(iv));
  if (send_result == CHANNEL_FAILURE) { exit(1); }

  yield();

  memset(out_cleartext, 0x00, sizeof(out_cleartext));
  recv_result = channel_recv(remote_ciphertext, sizeof(remote_ciphertext));
  if (recv_result == CHANNEL_FAILURE) { exit(1); }
  aes_result = aes_gcm_decrypt_and_verify( sir_dhm_context.secret_component, 
                                           remote_ciphertext, 
                                           remote_ciphertext + 144, 
                                           remote_ciphertext + 128, 
                                           out_cleartext ); 
  if (aes_result == AES_GCM_FAILURE) { exit(1); }
  send_result = channel_send(out_cleartext, sizeof(out_cleartext));
  if (send_result == CHANNEL_FAILURE) { exit(1); }

  yield();
  //while (1) { yield(); }
}


void sir_init(uint8_t *stack, uint8_t *heap, uint8_t *recv, uint8_t *send) 
{
  __asm("pushq %%rbp":::);
  __asm("pushq %%rbx":::);
  __asm("pushq %%r12":::);
  __asm("pushq %%r13":::);
  __asm("pushq %%r14":::);
  __asm("pushq %%r15":::);

  __asm("movq %%rsp, %0":"=r"(host_rsp)::);
  sir_rsp = (uint64_t) stack + 1048568;
  __asm("movq %0, %%rsp"::"r"(sir_rsp):);

  stack_buf = (uint8_t *) sir_rsp;
  heap_buf = (uint8_t *) heap;
  recv_buf = recv; 
  send_buf = send;

  L_main();
}

