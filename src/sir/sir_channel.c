#include <stdint.h>
#include <string.h>
#include "sir_channel.h"

static uint8_t *send_buf_start;
static uint64_t send_buf_size;
static uint8_t *send_buf_current;

static uint8_t *recv_buf_start;
static uint64_t recv_buf_size; 
static uint8_t *recv_buf_current;

void channel_send_init(uint8_t *send_buf, uint64_t size)
{
    send_buf_start = send_buf;
    send_buf_current = send_buf;
    send_buf_size = size;
}

void channel_send_reset()
{
    send_buf_current = send_buf_start;
}

void channel_recv_init(uint8_t *recv_buf, uint64_t size)
{
    recv_buf_start = recv_buf;
    recv_buf_current = recv_buf;
    recv_buf_size = size;
}

void channel_recv_reset()
{
    recv_buf_current = recv_buf_start;
}

channel_api_result_t channel_send(uint8_t *buf, uint64_t size)
{
    if (((send_buf_current + size) < (send_buf_start + send_buf_size)) &&
        ((send_buf_current + size) >= send_buf_current)) //account for overflow
    {
        memcpy(send_buf_current, buf, size); 
        send_buf_current += size;
        return CHANNEL_SUCCESS;
    }
    else {
        return CHANNEL_FAILURE;
    }
}

channel_api_result_t channel_recv(uint8_t *buf, uint64_t size)
{
    if (((recv_buf_current + size) < (recv_buf_start + recv_buf_size)) &&
        ((recv_buf_current + size) >= recv_buf_current)) //account for overflow
    {
        memcpy(buf, recv_buf_current, size); 
        recv_buf_current += size;
        return CHANNEL_SUCCESS;
    }
    else {
        return CHANNEL_FAILURE;
    }
}
