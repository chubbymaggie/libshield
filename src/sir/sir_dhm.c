#include "rand/drng.h"
#include "sir_dhm.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <stdint.h>
#endif


#if defined(MBEDTLS_DHM_C)
#if defined(MBEDTLS_BIGNUM_C)

#include "mbedtls/dhm.h"
#endif /* defined(MBEDTLS_DHM_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */


#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_exit       exit
#define mbedtls_free       free
#define mbedtls_calloc     calloc
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;


/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * Use Intel's DRNG to generate random numbers
 */

static int rnd_true_rand( void *rng_state, unsigned char *output, size_t len )
{
  int r = rdrand_get_bytes(len, output);
  return (r != DRNG_SUCCESS) ? 1 : 0; 
}

#if defined(MBEDTLS_DHM_C)
#if defined(MBEDTLS_BIGNUM_C)

#define TEST_ASSERT( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            goto exit;                              \
        }                                           \
    } while( 0 )


static const int DHM_radix_P = 16;
static const int DHM_radix_G = 16;
static mbedtls_dhm_context dhm_ctx;
static unsigned char dhm_pub[1000];
static unsigned char dhm_sec[1000];
static size_t dhm_sec_len;
static rnd_pseudo_info rnd_info;

dhm_make_public_params_ret_t dhm_make_public_params()
{
    dhm_make_public_params_ret_t return_value;

    memset( dhm_pub, 0x00, 1000 );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );
    return_value.outcome = DHM_FAILURE;
    return_value.dhm_pub = dhm_pub;
    return_value.dhm_pub_size = 1000;

    mbedtls_dhm_init( &dhm_ctx );
    TEST_ASSERT( mbedtls_mpi_read_string( &dhm_ctx.P, DHM_radix_P, MBEDTLS_DHM_RFC3526_MODP_3072_P) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &dhm_ctx.G, DHM_radix_G, MBEDTLS_DHM_RFC3526_MODP_3072_G ) == 0 );
    dhm_ctx.len = mbedtls_mpi_size( &dhm_ctx.P );

    TEST_ASSERT( mbedtls_dhm_make_public( &dhm_ctx, dhm_ctx.len, dhm_pub, dhm_ctx.len, &rnd_true_rand, &rnd_info ) == 0 );
    return_value.outcome = DHM_SUCCESS;
exit:
    return return_value;
}

dhm_compute_secret_ret_t dhm_compute_secret(uint8_t *remote_public)
{
    dhm_compute_secret_ret_t return_value;

    memset( dhm_sec, 0x00, 1000 );
    return_value.outcome = DHM_FAILURE;

    TEST_ASSERT( mbedtls_dhm_read_public( &dhm_ctx, remote_public, dhm_ctx.len ) == 0 );
    TEST_ASSERT( mbedtls_dhm_calc_secret( &dhm_ctx, dhm_sec, sizeof( dhm_sec ), &dhm_sec_len, &rnd_true_rand, &rnd_info ) == 0 );
    TEST_ASSERT( dhm_sec_len != 0 );

    return_value.dhm_sec = dhm_sec;
    return_value.dhm_sec_size = dhm_sec_len;
    return_value.outcome = DHM_SUCCESS;
exit:
    mbedtls_dhm_free( &dhm_ctx );
    return return_value;
}


#endif /* defined(MBEDTLS_DHM_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */

