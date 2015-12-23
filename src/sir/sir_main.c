#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "rand/drng.h"
#include "crypto/include/mbedtls/memory_buffer_alloc.h"
#include "sir_dhm.h"
#include "sir_aes_gcm.h"
#include "sir_channel.h"

void U_main()
{
  uint8_t cleartext[128];
  char *passphrase = "hellofirst";

  sir_send((uint8_t *) passphrase, strlen(passphrase) + 1);

  yield();

  sir_recv(cleartext, strlen(passphrase) + 1);
  channel_send(cleartext, strlen(passphrase) + 1);

  yield();
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

  init_channel(platform_config.send_buf, 4096, platform_config.recv_buf, 4096, NULL);
  mbedtls_memory_buffer_alloc_init( platform_config.heap_buf, 1048576 );
  dhm_result = dhm_make_public_params(&sir_dhm_context);
  if (dhm_result == DHM_FAILURE) { exit(1); }
  send_result = channel_send(sir_dhm_context.public_component, 1000);
  if (send_result == CHANNEL_FAILURE) { exit(1); }

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
  aes_result = aes_gcm_encrypt_and_tag(sir_dhm_context.secret_component, 
                                       cleartext, 
                                       iv, 
                                       tag, 
                                       ciphertext);  
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

  init_channel(platform_config.send_buf, 4096, 
               platform_config.recv_buf, 4096, 
               sir_dhm_context.secret_component);
  U_main();
}


