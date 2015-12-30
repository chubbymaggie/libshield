#include <string.h>
#include <stdint.h>
#include "platform.h"
#include "rand/drng.h"
#include "crypto/include/mbedtls/memory_buffer_alloc.h"
#include "sir_dhm.h"
#include "sir_aes_gcm.h"
#include "sir_channel.h"
#include "../common/message.h"

#define CHECK_SEND( TEST ) if( TEST == CHANNEL_FAILURE) { exit(1); }
#define CHECK_RECV( TEST ) if( TEST == CHANNEL_FAILURE) { exit(1); }
#define CHECK_AES( TEST )  if( TEST == AES_GCM_FAILURE) { exit(1); }
#define CHECK_DHM( TEST )  if( TEST == DHM_FAILURE) { exit(1); }
#define CHECK_DRNG( TEST ) if( TEST != DRNG_SUCCESS) { exit(1); }

void U_main()
{
  uint8_t cleartext[128];
  char *passphrase = "libshield";

  memset(cleartext, 0x00, 128);
  CHECK_SEND( sir_send((uint8_t *) passphrase, strlen(passphrase) + 1) );
  CHECK_RECV( sir_recv(cleartext, strlen(passphrase) + 1) );
  CHECK_SEND( channel_send(PRINT_DEBUG_MESSAGE, cleartext, strlen(passphrase) + 1) );
  CHECK_SEND( channel_send(EXIT_MESSAGE, NULL, 0) );
}


void L_main() 
{
  sir_dhm_context_t sir_dhm_context;

  init_channel(platform_config.send_buf, 4096, platform_config.recv_buf, 4096, NULL);
  mbedtls_memory_buffer_alloc_init( platform_config.heap_buf, 1048576 );

  /* generate local's DHM public key */
  CHECK_DHM( dhm_make_public_params(&sir_dhm_context) );

  /* send DHM public key to remote */
  CHECK_SEND( channel_send(SEND_DHM_PUBLIC, sir_dhm_context.public_component, 1000) );

  /* recv remote's DHM public key */
  CHECK_RECV( channel_recv(RECV_DHM_PUBLIC, sir_dhm_context.remote_component, 1000) );

  /* compute DHM secret using local and remote keys */
  CHECK_DHM( dhm_compute_secret(&sir_dhm_context) );

  /* initialize channel with DHM secret as AES key */
  init_channel(platform_config.send_buf, 4096, 
               platform_config.recv_buf, 4096, 
               sir_dhm_context.secret_component);

  U_main();
}


