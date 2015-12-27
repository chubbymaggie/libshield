#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "rand/drng.h"
#include "crypto/include/mbedtls/memory_buffer_alloc.h"
#include "sir_dhm.h"
#include "sir_aes_gcm.h"
#include "sir_channel.h"

#define CHECK_SEND( TEST ) if( TEST == CHANNEL_FAILURE) { exit(1); }
#define CHECK_RECV( TEST ) if( TEST == CHANNEL_FAILURE) { exit(1); }
#define CHECK_AES( TEST )  if( TEST == AES_GCM_FAILURE) { exit(1); }
#define CHECK_DHM( TEST )  if( TEST == DHM_FAILURE) { exit(1); }
#define CHECK_DRNG( TEST ) if( TEST != DRNG_SUCCESS) { exit(1); }

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
  sir_dhm_context_t sir_dhm_context;
  uint8_t remote_ciphertext[160];
  uint8_t ciphertext[128];
  uint8_t tag[16];
  uint8_t iv[16];
  uint8_t random_bytes[16];
  uint8_t cleartext[128];
  uint8_t out_cleartext[128];
  uint8_t constant_one = 1;
  size_t constant_384 = 384;

  init_channel(platform_config.send_buf, 4096, platform_config.recv_buf, 4096, NULL);
  mbedtls_memory_buffer_alloc_init( platform_config.heap_buf, 1048576 );
  CHECK_DHM( dhm_make_public_params(&sir_dhm_context) );
  CHECK_SEND( channel_send(sir_dhm_context.public_component, 1000) );

  yield();

  /* recv remote's DHM public key */
  CHECK_RECV( channel_recv(sir_dhm_context.remote_component, 1000) );
  CHECK_DHM( dhm_compute_secret(&sir_dhm_context) );

  /* output some junk */
  memset(iv, 0, 16);
  CHECK_DRNG( rdrand_get_bytes(16, iv) );
  CHECK_DRNG( rdrand_get_bytes(16, random_bytes) );

  CHECK_SEND( channel_send((uint8_t *) hello, strlen(hello) + 1) );
  CHECK_SEND( channel_send(&constant_one, sizeof(uint8_t)) );
  CHECK_SEND( channel_send(iv, 16) );
  CHECK_SEND( channel_send(random_bytes, 16) );
  CHECK_SEND( channel_send((uint8_t *) &constant_384, sizeof(uint64_t)) ); 
  CHECK_SEND( channel_send(sir_dhm_context.secret_component, sizeof(sir_dhm_context.secret_component)) ); 

  memcpy(cleartext, "pldi2016", strlen("pldi2016") + 1);
  CHECK_AES( aes_gcm_encrypt_and_tag(sir_dhm_context.secret_component, 
                                     cleartext, 
                                     iv, 
                                     tag, 
                                     ciphertext) );  
  CHECK_SEND( channel_send(ciphertext, sizeof(ciphertext)) );
  CHECK_SEND( channel_send(tag, sizeof(tag)) );
  CHECK_SEND( channel_send(iv, sizeof(iv)) );

  yield();

  memset(out_cleartext, 0x00, sizeof(out_cleartext));
  CHECK_RECV( channel_recv(remote_ciphertext, sizeof(remote_ciphertext)) );
  CHECK_AES( aes_gcm_decrypt_and_verify( sir_dhm_context.secret_component, 
                                         remote_ciphertext, 
                                         remote_ciphertext + 144, 
                                         remote_ciphertext + 128, 
                                         out_cleartext ) ); 
  CHECK_SEND( channel_send(out_cleartext, sizeof(out_cleartext)) );

  yield();

  init_channel(platform_config.send_buf, 4096, 
               platform_config.recv_buf, 4096, 
               sir_dhm_context.secret_component);
  U_main();
}


