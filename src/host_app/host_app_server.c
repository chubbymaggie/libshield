#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <czmq.h>

/* these parameters should be in a SIR config file */
#define SIR_URL "./libsir.so"
#define SIR_STACKSIZE 1048576
#define SIR_HEAPSIZE 1048576
#define SIR_RECVBUFSIZE 4096
#define SIR_SENDBUFSIZE 4096

typedef void (*sir_init_t)(uint8_t *, uint8_t *, uint8_t *, uint8_t *);
typedef void (*sir_main_t)();

int main(int argc, char **argv)
{
    int i;
    zctx_t *ctx = zctx_new();
    assert (ctx);
    void *socket = zsocket_new(ctx, ZMQ_PAIR);
    int success = zsocket_bind (socket, "tcp://127.0.0.1:5555");
    assert (success = 5555);
    printf("Waiting for requests on tcp://127.0.0.1:5555...\n");

    uint8_t remote_public[1000];
    printf("Recieving remote's DMH public key...\n");
    zmq_recv(socket, remote_public, sizeof(remote_public), 0);

    //grab handle to sir main function
    void *handle = dlopen(SIR_URL, RTLD_LAZY);
    if (handle == NULL) {
        printf("Unable to load SIR binary: %s\n", SIR_URL);
        exit(1);
    }
    sir_init_t sir_init = (sir_init_t) dlsym(handle, "sir_init");
    sir_main_t sir_main = (sir_main_t) dlsym(handle, "sir_main");
    
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

    printf("Creating SIR...\n");
    //sir_init(stack_region, heap_region, input_region, output_region)
    sir_init(ptr1, ptr2, ptr3, ptr4);

    printf("Sending SIR's DMH public key to remote...\n");
    zmq_send(socket, ptr4, 1000, 0);
    memcpy(ptr3, remote_public, sizeof(remote_public));
    printf("Computing Diffie-Hellman-Merkle secret...\n");
    sir_main();

    /* post-SIR computation, which should start with DestroyIsolatedRegion */
    printf("sir says: %s\n", ptr4);
    uint8_t is_rand_success = *((uint8_t *) ptr4 + strlen(ptr4) + 1);
    if (is_rand_success == 1) {
      uint8_t iv[16];
      memcpy(iv, ptr4 + strlen(ptr4) + 2, 16);
      int i;
      printf("sir gives us random bytes: ");
	  for (i = 0; i < 16; ++i)
      {
		 printf("%02x", iv[i]);
	  }
      printf("\n");
    }
    uint64_t secret_size;
    memcpy(&secret_size, (uint8_t *) ptr4 + strlen(ptr4) + 18, sizeof(uint64_t));
    printf("sir computes a secret of size %lu bytes: ", secret_size);
	for (i = 0; i < secret_size; ++i)
    {
	  printf("%02x", *((uint8_t *) ptr4 + strlen(ptr4) + 18 + sizeof(uint64_t) + i));
	}
    printf("\n");

    printf("sir computes a ciphertext: ");
	for (i = 0; i < 128; ++i)
    {
	  printf("%02x", *((uint8_t *) ptr4 + strlen(ptr4) + 18 + sizeof(uint64_t) + secret_size + i));
	}
    printf(", along with the tag: ");
	for (i = 0; i < 16; ++i)
    {
	  printf("%02x", *((uint8_t *) ptr4 + strlen(ptr4) + 18 + sizeof(uint64_t) + secret_size + 128 + i));
	}
    printf("\n");
    
    printf("sending ciphertext to remote...\n"); 
    uint8_t local_ciphertext[160];
    memcpy(local_ciphertext, ((uint8_t *) ptr4 + strlen(ptr4) + 18 + sizeof(uint64_t) + secret_size), 128);
    memcpy(local_ciphertext + 128, ((uint8_t *) ptr4 + strlen(ptr4) + 18 + sizeof(uint64_t) + secret_size + 128), 16);
    memcpy(local_ciphertext + 144, ((uint8_t *) ptr4 + strlen(ptr4) + 18 + sizeof(uint64_t) + secret_size + 144), 16);
    zmq_send(socket, local_ciphertext, sizeof(local_ciphertext), 0);

    uint8_t remote_ciphertext[160];
    printf("recieving ciphertext from remote...\n"); 
    zmq_recv(socket, remote_ciphertext, sizeof(remote_ciphertext), 0);
    memcpy(ptr3 + sizeof(remote_public), remote_ciphertext, sizeof(remote_ciphertext));

    printf("answer: %s\n", (uint8_t *) ptr4 + strlen(ptr4) + 18 + sizeof(uint64_t) + secret_size + 160);
}
