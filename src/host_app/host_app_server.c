#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <czmq.h>
#include "../common/message.h"

/* these parameters should be in a SIR config file */
#define SIR_URL "./libsir.so"
#define SIR_STACKSIZE 1048576
#define SIR_HEAPSIZE 1048576
#define SIR_RECVBUFSIZE 4096
#define SIR_SENDBUFSIZE 4096

typedef void (*sir_init_t)(uint8_t *, uint8_t *, uint8_t *, uint8_t *);
typedef void (*sir_entry_t)();

int main(int argc, char **argv)
{
    int i, success;
    sir_message_header_t msg_header;
    zctx_t *ctx = zctx_new();
    assert (ctx);
    void *inbound_socket = zsocket_new(ctx, ZMQ_PULL);
    success = zsocket_bind (inbound_socket, "tcp://127.0.0.1:5555");
    void *outbound_socket = zsocket_new(ctx, ZMQ_PUSH);
    success = zsocket_bind (outbound_socket, "tcp://127.0.0.1:5556");

    printf("Connecting to remote on tcp://127.0.0.1:5555 and tcp://127.0.0.1:5556...\n");

    //grab handle to sir main function
    void *handle = dlopen(SIR_URL, RTLD_LAZY);
    if (handle == NULL) {
        printf("Unable to load SIR binary: %s\n", SIR_URL);
        exit(1);
    }
    sir_init_t sir_init = (sir_init_t) dlsym(handle, "sir_init");
    sir_entry_t sir_entry = (sir_entry_t) dlsym(handle, "sir_entry");
    
    /* allocate memory for SIR heap and SIR stack */
    /* This code will be supplanted by CreateIsolatedRegion */
    uint8_t *ptr1 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_STACKSIZE);
    uint8_t *ptr2 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_HEAPSIZE);
    
    /* allocate shared memory between app and SIR */
    uint8_t *ptr3 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_RECVBUFSIZE);
    uint8_t *ptr4 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_SENDBUFSIZE);

    if (!ptr1 || !ptr2 || !ptr3 || !ptr4) {
        printf("Unable to allocate enough memory for SIR\n");
        exit(1);
    }

    printf("Entering SIR to compute DMH public key...\n");

    sir_init(ptr1, ptr2, ptr3, ptr4);

    uint8_t *current_recv_ptr = ptr3;
    uint8_t *current_send_ptr = ptr4;

    memcpy(&msg_header, current_send_ptr, sizeof(msg_header));
    assert (msg_header.message_size == 1000 && 
            msg_header.message_type == SEND_DHM_PUBLIC);
    current_send_ptr += sizeof(msg_header);
    //send_buffer has 1000 bytes of DHM public parameters
    printf("Sending SIR's DMH public key to remote...\n");
    zmq_send(outbound_socket, current_send_ptr, 1000, 0);
    current_send_ptr += 1000;

    sir_entry();

    memcpy(&msg_header, current_send_ptr, sizeof(msg_header));
    current_send_ptr += sizeof(msg_header);
    assert (msg_header.message_size == 1000 && 
            msg_header.message_type == RECV_DHM_PUBLIC);
    uint8_t remote_public[1000];
    printf("Recieving remote's DMH public key...\n");
    zmq_recv(inbound_socket, remote_public, sizeof(remote_public), 0); 

    memcpy(current_recv_ptr, remote_public, sizeof(remote_public));
    current_recv_ptr += sizeof(remote_public);

    current_recv_ptr = ptr3;
    current_send_ptr = ptr4;

    printf("Computing Diffie-Hellman-Merkle secret...\n");
    sir_entry();

    do {
      memcpy(&msg_header, current_send_ptr, sizeof(msg_header));
      current_send_ptr += sizeof(msg_header);

      if (msg_header.message_type == RECV_ENCRYPTED_MESSAGE ||
          msg_header.message_type == RECV_MESSAGE) {
        printf("Handling RECV command from SIR\n");
        char *payload = malloc(msg_header.message_size);  
        if (! payload) { exit(1); }
        zmq_recv(inbound_socket, payload, msg_header.message_size, 0);
        memcpy(current_recv_ptr, payload, msg_header.message_size);
        current_recv_ptr += msg_header.message_size;
      }
      else if (msg_header.message_type == SEND_ENCRYPTED_MESSAGE ||
               msg_header.message_type == SEND_MESSAGE) {
        printf("Handling SEND command from SIR\n");
        zmq_send(outbound_socket, current_send_ptr, msg_header.message_size, 0);
        current_send_ptr += msg_header.message_size;
      }
      else if (msg_header.message_type == PRINT_DEBUG_MESSAGE) {
        printf("Handling PRINT command from SIR\n");
        char *payload = malloc(msg_header.message_size);  
        if (! payload) { exit(1); }
        memcpy(payload, current_send_ptr, msg_header.message_size);
        current_send_ptr += msg_header.message_size;
        printf("sir says: %s\n", payload);
        free(payload);
      }
      else if (msg_header.message_type == EXIT_MESSAGE) {
        printf("Handling EXIT command from SIR\n");
        break;
      }

      sir_entry();
    } while (true);

    zsocket_destroy(ctx, outbound_socket);
    zsocket_destroy(ctx, inbound_socket);
    zctx_destroy(&ctx);
}

