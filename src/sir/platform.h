#include <stdint.h>

typedef struct {
  uint8_t *stack_buf;
  uint8_t *heap_buf;
  uint8_t *recv_buf;
  uint8_t *send_buf;
  uint64_t sir_rsp;
  uint64_t host_rsp;
} platform_config_t;

extern platform_config_t platform_config;

void exit(uint64_t status);
void yield();
void sir_init(uint8_t *stack, uint8_t *heap, uint8_t *recv, uint8_t *send);
void sir_entry();
