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

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
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

int rand();

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

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
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}


#if defined(MBEDTLS_DHM_C)
#if defined(MBEDTLS_BIGNUM_C)

#define TEST_ASSERT( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            return_value = FAILURE;                 \
            goto exit;                              \
        }                                           \
    } while( 0 )

typedef enum {SUCCESS = 0, FAILURE = 1} result_t;

result_t test_suite_dhm_do_dhm( int radix_P, char *input_P,
                 int radix_G, char *input_G )
{
    result_t return_value;
    mbedtls_dhm_context ctx_srv;
    mbedtls_dhm_context ctx_cli;
    unsigned char ske[1000];
    unsigned char *p = ske;
    unsigned char pub_cli[1000];
    unsigned char sec_srv[1000];
    unsigned char sec_cli[1000];
    size_t ske_len = 0;
    size_t pub_cli_len = 0;
    size_t sec_srv_len;
    size_t sec_cli_len;
    int x_size;
    rnd_pseudo_info rnd_info;

    mbedtls_dhm_init( &ctx_srv );
    mbedtls_dhm_init( &ctx_cli );
    memset( ske, 0x00, 1000 );
    memset( pub_cli, 0x00, 1000 );
    memset( sec_srv, 0x00, 1000 );
    memset( sec_cli, 0x00, 1000 );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    /*
     * Set params
     */
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_srv.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_srv.G, radix_G, input_G ) == 0 );
    x_size = mbedtls_mpi_size( &ctx_srv.P );
    pub_cli_len = x_size;

    /*
     * First key exchange
     */
    TEST_ASSERT( mbedtls_dhm_make_params( &ctx_srv, x_size, ske, &ske_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    ske[ske_len++] = 0;
    ske[ske_len++] = 0;
    TEST_ASSERT( mbedtls_dhm_read_params( &ctx_cli, &p, ske + ske_len ) == 0 );

    TEST_ASSERT( mbedtls_dhm_make_public( &ctx_cli, x_size, pub_cli, pub_cli_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_dhm_read_public( &ctx_srv, pub_cli, pub_cli_len ) == 0 );

    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_srv, sec_srv, sizeof( sec_srv ), &sec_srv_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_cli, sec_cli, sizeof( sec_cli ), &sec_cli_len, NULL, NULL ) == 0 );

    TEST_ASSERT( sec_srv_len == sec_cli_len );
    TEST_ASSERT( sec_srv_len != 0 );
    TEST_ASSERT( memcmp( sec_srv, sec_cli, sec_srv_len ) == 0 );
    return_value = SUCCESS;

exit:
    mbedtls_dhm_free( &ctx_srv );
    mbedtls_dhm_free( &ctx_cli );
    return return_value;
}

#endif /* defined(MBEDTLS_DHM_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */

