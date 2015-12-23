#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "sir_channel.h"
#include "sir_aes_gcm.h"
#include "rand/drng.h"

static sir_channel_context_t sir_channel_context;

void init_channel(uint8_t *send_buf_start, 
                  uint64_t send_buf_size,
                  uint8_t *recv_buf_start,
                  uint64_t recv_buf_size,
                  uint8_t *key)
{
    sir_channel_context.send_buf_start = send_buf_start;
    sir_channel_context.send_buf_current = send_buf_start;
    sir_channel_context.send_buf_size = send_buf_size;
    sir_channel_context.recv_buf_start = recv_buf_start;
    sir_channel_context.recv_buf_current = recv_buf_start;
    sir_channel_context.recv_buf_size = recv_buf_size;
    sir_channel_context.symmetric_key = key;
}

channel_api_result_t channel_send(uint8_t *buf, uint64_t size)
{
    if (((sir_channel_context.send_buf_current + size) < 
         (sir_channel_context.send_buf_start + sir_channel_context.send_buf_size)) 
        &&
        ((sir_channel_context.send_buf_current + size) >= sir_channel_context.send_buf_current)
       ) //account for overflow
    {
        memcpy(sir_channel_context.send_buf_current, buf, size); 
        sir_channel_context.send_buf_current += size;
        return CHANNEL_SUCCESS;
    }
    else {
        return CHANNEL_FAILURE;
    }
}

channel_api_result_t channel_recv(uint8_t *buf, uint64_t size)
{
    if (((sir_channel_context.recv_buf_current + size) < 
         (sir_channel_context.recv_buf_start + sir_channel_context.recv_buf_size)) 
        &&
        ((sir_channel_context.recv_buf_current + size) >= sir_channel_context.recv_buf_current)
       ) //account for overflow
    {
        memcpy(buf, sir_channel_context.recv_buf_current, size); 
        sir_channel_context.recv_buf_current += size;
        return CHANNEL_SUCCESS;
    }
    else {
        return CHANNEL_FAILURE;
    }
}

channel_api_result_t sir_send(uint8_t *buf, uint64_t size)
{
    aes_gcm_api_result_t aes_result;
    uint8_t buf_128_bytes[128];
    uint8_t ciphertext[128];
    uint8_t iv[16];
    uint8_t tag[16];
    int rng_result;

    if (size > 128) 
    { 
        return CHANNEL_FAILURE; /* larger messages are not yet supported */
    } 
    if (sir_channel_context.symmetric_key == NULL) /* send without encrypting */ 
    { 
        return channel_send(buf, size); 
    }
    
    memset(buf_128_bytes, 0x00, sizeof(buf_128_bytes));
    memcpy(buf_128_bytes, buf, size);
    rng_result = rdrand_get_bytes(16, iv);
    if (rng_result != DRNG_SUCCESS) { exit(1); }
    aes_result = aes_gcm_encrypt_and_tag(sir_channel_context.symmetric_key, 
                                         buf_128_bytes, 
                                         iv, 
                                         tag, 
                                         ciphertext);

    if (aes_result == AES_GCM_FAILURE) {
        return CHANNEL_FAILURE;
    }

    channel_send(ciphertext, 128);
    channel_send(iv, 16);
    channel_send(tag, 16);
    return CHANNEL_SUCCESS;
}

channel_api_result_t sir_recv(uint8_t *buf, uint64_t size)
{
    aes_gcm_api_result_t aes_result;
    uint8_t cleartext[128];
    uint8_t ciphertext[128];
    uint8_t iv[16];
    uint8_t tag[16];

    if (size > 128) 
    { 
        return CHANNEL_FAILURE; /* larger messages are not yet supported */
    } 
    if (sir_channel_context.symmetric_key == NULL) /* recv without decrypting */ 
    { 
        return channel_recv(buf, size); 
    }
    
    channel_recv(ciphertext, 128);
    channel_recv(iv, 16);
    channel_recv(tag, 16);

    aes_result = aes_gcm_decrypt_and_verify(sir_channel_context.symmetric_key, 
                                            ciphertext, 
                                            iv, 
                                            tag, 
                                            cleartext);

    if (aes_result == AES_GCM_FAILURE) {
        return CHANNEL_FAILURE;
    }

    memcpy(buf, cleartext, size);
    return CHANNEL_SUCCESS;
}
