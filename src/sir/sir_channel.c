#include <stdint.h>
#include <stdbool.h>
#include "string/libstring.h"
#include "platform.h"
#include "sir_channel.h"
#include "sir_aes_gcm.h"
#include "rand/drng.h"
#include "../common/message.h"

#define NULL ((void *)0)
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

static sir_channel_context_t sir_channel_context;

/*@ requires sir_channel_context.recv_buf_current < (sir_channel_context.recv_buf_start +
                                                     sir_channel_context.recv_buf_size);
    requires size > 0 && size < 4096;
    assigns \nothing;
    behavior space_left_in_recv_buf:
      assumes ((sir_channel_context.recv_buf_current + size) < 
               (sir_channel_context.recv_buf_start + sir_channel_context.recv_buf_size) &&
               (sir_channel_context.recv_buf_current) < 
               (sir_channel_context.recv_buf_current + size));
      ensures \result == 1;
    behavior out_of_space_in_recv_buf:
      assumes !((sir_channel_context.recv_buf_current + size) < 
               (sir_channel_context.recv_buf_start + sir_channel_context.recv_buf_size) &&
               (sir_channel_context.recv_buf_current) < 
               (sir_channel_context.recv_buf_current + size));
      ensures \result == 0;
    complete behaviors space_left_in_recv_buf, out_of_space_in_recv_buf;
    disjoint behaviors space_left_in_recv_buf, out_of_space_in_recv_buf;
 */
bool bytes_available_in_recv_buf(uint64_t size)
{
  if (((sir_channel_context.recv_buf_current + size) < 
       (sir_channel_context.recv_buf_start + sir_channel_context.recv_buf_size)) 
      &&
       ((sir_channel_context.recv_buf_current + size) >= 
        (sir_channel_context.recv_buf_current)) ) { return true; } else { return false; }
}

/*@ requires sir_channel_context.send_buf_current < (sir_channel_context.send_buf_start +
                                                     sir_channel_context.send_buf_size);
    requires size > 0 && size < 4096;
    assigns \nothing;
    behavior space_left_in_send_buf:
      assumes ((sir_channel_context.send_buf_current + size) < 
               (sir_channel_context.send_buf_start + sir_channel_context.send_buf_size) &&
               (sir_channel_context.send_buf_current) < 
               (sir_channel_context.send_buf_current + size)) == \true;
      ensures \result == 1;
    behavior out_of_space_in_send_buf:
      assumes ((sir_channel_context.send_buf_current + size) < 
               (sir_channel_context.send_buf_start + sir_channel_context.send_buf_size) &&
               (sir_channel_context.send_buf_current) < 
               (sir_channel_context.send_buf_current + size)) == \false;
      ensures \result == 0;
    complete behaviors space_left_in_send_buf, out_of_space_in_send_buf;
    disjoint behaviors space_left_in_send_buf, out_of_space_in_send_buf;
 */
bool bytes_available_in_send_buf(uint64_t size)
{
  if (((sir_channel_context.send_buf_current + size) < 
       (sir_channel_context.send_buf_start + sir_channel_context.send_buf_size)) 
      &&
       ((sir_channel_context.send_buf_current + size) >= 
        (sir_channel_context.send_buf_current)) ) { return true; } else { return false; }
}

/*@ requires \valid(send_buf_start+ (0..send_buf_size-1));
    requires \valid(recv_buf_start+ (0..recv_buf_size-1));
    requires send_buf_size == 4096 && recv_buf_size == 4096;
    requires send_buf_size > 0 && recv_buf_size > 0;
    requires \separated(send_buf_start+ (0..send_buf_size-1), 
                        recv_buf_start+ (0..recv_buf_size-1));
    requires (send_buf_start < send_buf_start + send_buf_size) &&
             (recv_buf_start < recv_buf_start + recv_buf_size);
    assigns sir_channel_context;
    ensures \separated(sir_channel_context.send_buf_start+ (0..sir_channel_context.send_buf_size-1), 
                       sir_channel_context.recv_buf_start+ (0..sir_channel_context.recv_buf_size-1));
    ensures sir_channel_context.send_buf_start == send_buf_start;
    ensures sir_channel_context.send_buf_current == send_buf_start;
    ensures sir_channel_context.send_buf_size == 4096;
    ensures sir_channel_context.recv_buf_start == recv_buf_start;
    ensures sir_channel_context.recv_buf_current == recv_buf_start;
    ensures sir_channel_context.recv_buf_size == 4096;
    ensures sir_channel_context.symmetric_key == key;
 */
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

/*@ requires size > 0 && size < 4080;
    requires sir_channel_context.send_buf_current < (sir_channel_context.send_buf_start +
                                                     sir_channel_context.send_buf_size);
    requires \valid(sir_channel_context.send_buf_start+ (0..sir_channel_context.send_buf_size-1));
    requires \valid(sir_channel_context.send_buf_current+ (0..size+15));
    assigns \old(sir_channel_context.send_buf_current)[0..size+15], 
            sir_channel_context.send_buf_current;
 */
channel_api_result_t channel_send(message_type_t type, uint8_t *buf, uint64_t size)
{
    sir_message_header_t msg_header;

    msg_header.message_type = type;
    msg_header.message_size = size;

    if (bytes_available_in_send_buf(size + sizeof(sir_message_header_t)) == false) { 
      return CHANNEL_FAILURE; 
    }

    uint8_t *msg_header_ptr = (uint8_t *) &msg_header;
    //@ assert sir_channel_context.send_buf_current <= (sir_channel_context.send_buf_current + size + 16);
    //@ assert \valid(sir_channel_context.send_buf_current+ (0..size+15));
    //@ assert \valid((uint8_t *)msg_header_ptr+ (0..15));
    memcpy(sir_channel_context.send_buf_current, (uint8_t *) &msg_header, sizeof(msg_header)); 
    sir_channel_context.send_buf_current += sizeof(msg_header);

    if (size > 0) {
      memcpy(sir_channel_context.send_buf_current, buf, size); 
      sir_channel_context.send_buf_current += size;
    }

    yield(); // untrusted code must send it to remote 
    return CHANNEL_SUCCESS;
}

channel_api_result_t channel_recv(message_type_t type, uint8_t *buf, uint64_t size)
{
    sir_message_header_t msg_header;

    // first transmit the header so that host knows we want size number of bytes 
    if (bytes_available_in_send_buf(sizeof(msg_header)) == false) { return CHANNEL_FAILURE; }

    msg_header.message_type = type;
    msg_header.message_size = size;
    memcpy(sir_channel_context.send_buf_current, (void *) &msg_header, sizeof(msg_header)); 
    sir_channel_context.send_buf_current += sizeof(msg_header);

    yield(); // let the host get those bytes for us 

    // first retrieve the header
    if (bytes_available_in_recv_buf(size) == false) { return CHANNEL_FAILURE; }

    memcpy(buf, sir_channel_context.recv_buf_current, size);
    sir_channel_context.recv_buf_current += size; //skip past the end

    return CHANNEL_SUCCESS;
}

channel_api_result_t sir_send(uint8_t *buf, uint64_t size)
{
    aes_gcm_api_result_t aes_result;
    channel_api_result_t send_result;
    uint8_t buf_128_bytes[128];
    uint8_t ciphertext[160];
    int rng_result;

    if (size > 128) 
    { 
        return CHANNEL_FAILURE; // larger messages are not yet supported - need malloc
    }

    if (sir_channel_context.symmetric_key == NULL) // send without encrypting 
    { 
        return channel_send(SEND_MESSAGE, buf, size); 
    }
    
    memset(buf_128_bytes, 0x00, sizeof(buf_128_bytes));
    memcpy(buf_128_bytes, buf, size);

    // generate new, random IV 
    rng_result = rdrand_get_bytes(16, ciphertext + 128);
    if (rng_result != DRNG_SUCCESS) { exit(1); }

    aes_result = aes_gcm_encrypt_and_tag(sir_channel_context.symmetric_key, 
                                         buf_128_bytes, 
                                         ciphertext + 128, 
                                         ciphertext + 144, 
                                         ciphertext + 0);

    if (aes_result == AES_GCM_FAILURE) { return CHANNEL_FAILURE; }

    send_result = channel_send(SEND_ENCRYPTED_MESSAGE, ciphertext, 160);
    if (send_result == CHANNEL_FAILURE) { return CHANNEL_FAILURE; }

    return CHANNEL_SUCCESS;
}

channel_api_result_t sir_recv(uint8_t *buf, uint64_t size)
{
    aes_gcm_api_result_t aes_result;
    channel_api_result_t recv_result;
    uint8_t cleartext[128];
    uint8_t ciphertext[160];

    if (size > 128) 
    { 
        return CHANNEL_FAILURE; // larger messages are not yet supported 
    } 

    if (sir_channel_context.symmetric_key == NULL) // recv without decrypting 
    { 
        return channel_recv(SEND_MESSAGE, buf, size); 
    }
    
    recv_result = channel_recv(RECV_ENCRYPTED_MESSAGE, ciphertext, 160);
    if (recv_result == CHANNEL_FAILURE) { return CHANNEL_FAILURE; }

    aes_result = aes_gcm_decrypt_and_verify(sir_channel_context.symmetric_key, 
                                            ciphertext, 
                                            ciphertext + 128, 
                                            ciphertext + 144, 
                                            cleartext);

    if (aes_result == AES_GCM_FAILURE) {
        return CHANNEL_FAILURE;
    }

    memcpy(buf, cleartext, size);
    return CHANNEL_SUCCESS;
}

