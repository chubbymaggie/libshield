#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

    //sir_init(stack_region, heap_region, input_region, output_region)
    sir_init(ptr1, ptr2, ptr3, ptr4);

    sir_main();

    /* post-SIR computation, which should start with DestroyIsolatedRegion */
    printf("sir says: %s\n", ptr4);
    uint8_t is_rand_success = *((uint8_t *) ptr4 + strlen(ptr4) + 1);
    if (is_rand_success == 1) {
      uint8_t iv[16];
      memcpy(iv, ptr4 + strlen(ptr4) + 1 + sizeof(uint8_t), 16);
      int i;
      printf("sir says: ");
	  for (i = 0; i < 16; ++i)
      {
		 printf("%02x", iv[i]);
	  }
      printf("\n");
    }
}
