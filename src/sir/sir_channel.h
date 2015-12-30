#ifndef SIR_CHANNEL_H
#define SIR_CHANNEL_H

#include <stdint.h>
#include "../common/message.h"

typedef enum {
  CHANNEL_SUCCESS = 0, 
  CHANNEL_FAILURE = 1
} channel_api_result_t;

/** Provides two unidirectional channels: one for send, and one for recv.
 *  Messages are encrypted by send, and decrypted by recv using 
 *  a symmetric cipher, specifically AES-GCM-256.
 *  A struct of type sir_channel_context_t has all state needed by 
 *  sir_send and sir_recv APIs.
 */
typedef struct {
  uint8_t *send_buf_start;     /* starting address of channel buffer */
  uint64_t send_buf_size;      /* size of channel buffer */
  uint8_t *send_buf_current;   /* current pointer in the channel buffer */
  uint8_t *recv_buf_start;     /* starting address of channel buffer */
  uint64_t recv_buf_size;      /* size of channel buffer */
  uint8_t *recv_buf_current;   /* current pointer in the channel buffer */
  uint8_t* symmetric_key;      /* secret 256-bit key for AES-GCM */
} sir_channel_context_t;

/**
 * \brief                        initialize channel with send and recv buffers.
 *                               Caller may optionally provide a key for crypto. 
 *
 * \param send_buf_start         starting address of send buffer in untrusted memory
 * \param send_buf_size          size of send buffer in untrusted memory
 * \param recv_buf_start         starting address of recv buffer in untrusted memory
 * \param recv_buf_size          size of recv buffer in untrusted memory
 * \param key                    optional key, must be set to NULL if crypto is not needed 
 *
 * \return                       CHANNEL_SUCCESS or CHANNEL_FAILURE
 */
void init_channel(uint8_t *send_buf_start, 
                  uint64_t send_buf_size,
                  uint8_t *recv_buf_start, 
                  uint64_t recv_buf_size,
                  uint8_t *key);

/**
 * \brief                        Encrypt and send the message to untrusted memory.
 *
 * \param buf                    starting address of message buffer in U's memory
 * \param size                   size of buffer
 *
 * \return                       CHANNEL_SUCCESS or CHANNEL_FAILURE
 */
channel_api_result_t sir_send(uint8_t *buf, uint64_t size);

/**
 * \brief                        Decrypt and recv the message from untrusted memory.
 *                               Places the decrypted contents in the input buffer.
 *
 * \param buf                    starting address of recepient buffer in U's memory
 * \param size                   size of buffer 
 *
 * \return                       CHANNEL_SUCCESS or CHANNEL_FAILURE
 */
channel_api_result_t sir_recv(uint8_t *buf, uint64_t size);

/* channel_send is an internal API, and is used by DHM and sir_send */
channel_api_result_t channel_send(message_type_t type, uint8_t *buf, uint64_t size);

/* channel_recv is an internal API, and is used by DHM and sir_recv */
channel_api_result_t channel_recv(message_type_t type, uint8_t *buf, uint64_t size);


#endif /* SIR_CHANNEL_H */
