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


#define DHM_radix_P 16
#define DHM_radix_G 16

dhm_api_result_t dhm_make_public_params(sir_dhm_context_t *sir_dhm_context)
{
    dhm_api_result_t dhm_api_result;

    memset( sir_dhm_context->public_component, 0x00, sizeof(sir_dhm_context->public_component) );
    memset( &sir_dhm_context->rnd_info, 0x00, sizeof( rnd_pseudo_info ) );
    dhm_api_result = DHM_FAILURE;

    mbedtls_dhm_init( &sir_dhm_context->mbedtls_ctx );
    TEST_ASSERT( mbedtls_mpi_read_string( &sir_dhm_context->mbedtls_ctx.P, 
                                          DHM_radix_P, 
                                          MBEDTLS_DHM_RFC3526_MODP_3072_P) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &sir_dhm_context->mbedtls_ctx.G, 
                                          DHM_radix_G, 
                                          MBEDTLS_DHM_RFC3526_MODP_3072_G ) == 0 );
    sir_dhm_context->mbedtls_ctx.len = mbedtls_mpi_size( &sir_dhm_context->mbedtls_ctx.P );

    TEST_ASSERT( mbedtls_dhm_make_public( &sir_dhm_context->mbedtls_ctx, 
                                          sir_dhm_context->mbedtls_ctx.len, 
                                          sir_dhm_context->public_component, 
                                          sir_dhm_context->mbedtls_ctx.len, 
                                          &rnd_true_rand, 
                                          &sir_dhm_context->rnd_info ) == 0 );
    dhm_api_result = DHM_SUCCESS;
exit:
    return dhm_api_result;
}

dhm_api_result_t dhm_compute_secret(sir_dhm_context_t *sir_dhm_context)
{
    dhm_api_result_t dhm_api_result;
    size_t secret_length;

    memset( sir_dhm_context->secret_component, 0x00, sizeof(sir_dhm_context->secret_component) );
    dhm_api_result = DHM_FAILURE;

    TEST_ASSERT( mbedtls_dhm_read_public( &sir_dhm_context->mbedtls_ctx, 
                                          sir_dhm_context->remote_component, 
                                          sir_dhm_context->mbedtls_ctx.len ) == 0 );
    TEST_ASSERT( mbedtls_dhm_calc_secret( &sir_dhm_context->mbedtls_ctx, 
                                          sir_dhm_context->secret_component, 
                                          sizeof( sir_dhm_context->secret_component ), 
                                          &secret_length, 
                                          &rnd_true_rand, 
                                          &sir_dhm_context->rnd_info ) == 0 );
    TEST_ASSERT( secret_length != 0 );

    dhm_api_result = DHM_SUCCESS;
exit:
    mbedtls_dhm_free( &sir_dhm_context->mbedtls_ctx );
    return dhm_api_result;
}


#endif /* defined(MBEDTLS_DHM_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */

