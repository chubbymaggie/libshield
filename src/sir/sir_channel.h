#ifndef SIR_CHANNEL_H
#define SIR_CHANNEL_H

typedef enum {CHANNEL_SUCCESS = 0, CHANNEL_FAILURE = 1} channel_api_result_t;

void channel_send_init(uint8_t *send_buf, uint64_t size);
void channel_send_reset();
channel_api_result_t channel_send(uint8_t *buf, uint64_t size);

void channel_recv_init(uint8_t *recv_buf, uint64_t size);
void channel_recv_reset();
channel_api_result_t channel_recv(uint8_t *buf, uint64_t size);

#endif /* SIR_CHANNEL_H */
