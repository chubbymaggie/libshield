#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>

typedef enum {
  INVALID_MESSAGE = 0,
  SEND_MESSAGE,
  SEND_ENCRYPTED_MESSAGE,
  RECV_MESSAGE,
  RECV_ENCRYPTED_MESSAGE,
  SEND_DHM_PUBLIC,
  RECV_DHM_PUBLIC,
  PRINT_DEBUG_MESSAGE,
  EXIT_MESSAGE
} message_type_t;

typedef struct {
  uint64_t message_type;
  uint64_t message_size;
} sir_message_header_t;

#endif //MESSAGE_H
