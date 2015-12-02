#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* these parameters should be in a SIR config file */
#define SIR_URL "libsir.so"
#define SIR_STACKSIZE 4096
#define SIR_HEAPSIZE 4096
#define SIR_RECVBUFSIZE 4096
#define SIR_SENDBUFSIZE 4096

typedef void (*sir_main_t)(uint8_t *, uint8_t *, uint8_t *, uint8_t *);

int main(int argc, char **argv)
{
    //grab handle to sir main function
    void *handle = dlopen(SIR_URL, RTLD_LAZY);
    if (handle == NULL) {
        printf("Unable to load SIR binary: %s\n", SIR_URL);
        exit(1);
    }
    sir_main_t sir_main = (sir_main_t) dlsym(handle, "sir_main");
    
    /* allocate memory for SIR heap and SIR stack */
    /* This code will be supplanted by CreateIsolatedRegion */
    uint8_t *ptr1 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_STACKSIZE);
    uint8_t *ptr2 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_HEAPSIZE);
    
    /* allocate shared memory between app and SIR */
    uint8_t *ptr3 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_RECVBUFSIZE);
    uint8_t *ptr4 = (uint8_t *) malloc(sizeof(uint8_t) * SIR_SENDBUFSIZE);

    //sir_main(stack_region, heap_region, input_region, output_region)
    sir_main(ptr1, ptr2, ptr3, ptr4);

    /* post-SIR computation, which should start with DestroyIsolatedRegion */
    printf("sir says: %s\n", ptr4);
}
