#include <string.h>
static unsigned char buf[1048576];
extern void mbedtls_memory_buffer_alloc_init( unsigned char *buf, size_t len );
extern void mbedtls_memory_buffer_alloc_free();

typedef enum {SUCCESS = 0, FAILURE = 1} result_t;
result_t test_suite_dhm_do_dhm( int radix_P, char *input_P,
                 int radix_G, char *input_G );

int main() {
  result_t result;
  char *input_P = "b3126aeaf47153c7d67f403030b292b5bd5a6c9eae1c137af34087fce2a36a578d70c5c560ad2bdb924c4a4dbee20a1671be7103ce87defa76908936803dbeca60c33e1289c1a03ac2c6c4e49405e5902fa0596a1cbaa895cc402d5213ed4a5f1f5ba8b5e1ed3da951a4c475afeb0ca660b7368c38c8e809f382d96ae19e60dc984e61cb42b5dfd723322acf327f9e413cda6400c15c5b2ea1fa34405d83982fba40e6d852da3d91019bf23511314254dc211a90833e5b1798ee52a78198c555644729ad92f060367c74ded37704adfc273a4a33fec821bd2ebd3bc051730e97a4dd14d2b766062592f5eec09d16bb50efebf2cc00dd3e0e3418e60ec84870f7";
  char *input_G = "800abfe7dc667aa17bcd7c04614bc221a65482ccc04b604602b0e131908a938ea11b48dc515dab7abcbb1e0c7fd66511edc0d86551b7632496e03df94357e1c4ea07a7ce1e381a2fcafdff5f5bf00df828806020e875c00926e4d011f88477a1b01927d73813cad4847c6396b9244621be2b00b63c659253318413443cd244215cd7fd4cbe796e82c6cf70f89cc0c528fb8e344809b31876e7ef739d5160d095c9684188b0c8755c7a468d47f56d6db9ea012924ecb0556fb71312a8d7c93bb2898ea08ee54eeb594548285f06a973cbbe2a0cb02e90f323fe045521f34c68354a6d3e95dbfff1eb64692edc0a44f3d3e408d0e479a541e779a6054259e2d854";
  mbedtls_memory_buffer_alloc_init( buf, sizeof( buf ) );
  result = test_suite_dhm_do_dhm(16, input_P, 16, input_G);
  if (result == FAILURE) { *((int *) 0) = 0; }
  mbedtls_memory_buffer_alloc_free( );
  return result;
}
