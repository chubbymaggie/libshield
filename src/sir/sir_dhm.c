#include "rand/drng.h"

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

/**
 * Use Intel's DRNG to generate random numbers
 */

static int rnd_true_rand( void *rng_state, unsigned char *output, size_t len )
{
  int r = rdrand_get_bytes(len, output);
  if (r != DRNG_SUCCESS) { exit(1); } 
  return 0;
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

static const int DHM_radix_P = 16;
static const char *DHM_P = "b3126aeaf47153c7d67f403030b292b5bd5a6c9eae1c137af34087fce2a36a578d70c5c560ad2bdb924c4a4dbee20a1671be7103ce87defa76908936803dbeca60c33e1289c1a03ac2c6c4e49405e5902fa0596a1cbaa895cc402d5213ed4a5f1f5ba8b5e1ed3da951a4c475afeb0ca660b7368c38c8e809f382d96ae19e60dc984e61cb42b5dfd723322acf327f9e413cda6400c15c5b2ea1fa34405d83982fba40e6d852da3d91019bf23511314254dc211a90833e5b1798ee52a78198c555644729ad92f060367c74ded37704adfc273a4a33fec821bd2ebd3bc051730e97a4dd14d2b766062592f5eec09d16bb50efebf2cc00dd3e0e3418e60ec84870f7";
static const int DHM_radix_G = 16;
static const char *DHM_G = "800abfe7dc667aa17bcd7c04614bc221a65482ccc04b604602b0e131908a938ea11b48dc515dab7abcbb1e0c7fd66511edc0d86551b7632496e03df94357e1c4ea07a7ce1e381a2fcafdff5f5bf00df828806020e875c00926e4d011f88477a1b01927d73813cad4847c6396b9244621be2b00b63c659253318413443cd244215cd7fd4cbe796e82c6cf70f89cc0c528fb8e344809b31876e7ef739d5160d095c9684188b0c8755c7a468d47f56d6db9ea012924ecb0556fb71312a8d7c93bb2898ea08ee54eeb594548285f06a973cbbe2a0cb02e90f323fe045521f34c68354a6d3e95dbfff1eb64692edc0a44f3d3e408d0e479a541e779a6054259e2d854";

static mbedtls_dhm_context dhm_ctx;
static unsigned char dhm_pub[1000];
static unsigned char dhm_sec[1000];

result_t dhm_make_public_params()
{
    result_t return_value;
    rnd_pseudo_info rnd_info;

    memset( dhm_pub, 0x00, 1000 );
    memset( dhm_sec, 0x00, 1000 );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    mbedtls_dhm_init( &dhm_ctx );
    TEST_ASSERT( mbedtls_mpi_read_string( &dhm_ctx.P, DHM_radix_P, DHM_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &dhm_ctx.G, DHM_radix_G, DHM_G ) == 0 );
    dhm_ctx.len = mbedtls_mpi_size( &dhm_ctx.P );

    TEST_ASSERT( mbedtls_dhm_make_public( &dhm_ctx, dhm_ctx.len, dhm_pub, dhm_ctx.len, &rnd_true_rand, &rnd_info ) == 0 );
    return_value = SUCCESS;
exit:
    mbedtls_dhm_free( &dhm_ctx );
    return return_value;
}

result_t dhm_test()
{
    result_t return_value;
    mbedtls_dhm_context ctx_srv;
    mbedtls_dhm_context ctx_cli;
    unsigned char pub_srv[1000];
    unsigned char pub_cli[1000];
    unsigned char sec_srv[1000];
    unsigned char sec_cli[1000];
    size_t sec_srv_len;
    size_t sec_cli_len;
    int x_size;
    rnd_pseudo_info rnd_info_srv;
    rnd_pseudo_info rnd_info_cli;

    mbedtls_dhm_init( &ctx_srv );
    mbedtls_dhm_init( &ctx_cli );
    //memset( ske, 0x00, 1000 );
    memset( pub_srv, 0x00, 1000 );
    memset( pub_cli, 0x00, 1000 );
    memset( sec_srv, 0x00, 1000 );
    memset( sec_cli, 0x00, 1000 );
    memset( &rnd_info_srv, 0x00, sizeof( rnd_pseudo_info ) );
    memset( &rnd_info_cli, 0x00, sizeof( rnd_pseudo_info ) );

    /*
     * Set params
     */
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_srv.P, DHM_radix_P, DHM_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_srv.G, DHM_radix_G, DHM_G ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_cli.P, DHM_radix_P, DHM_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_cli.G, DHM_radix_G, DHM_G ) == 0 );
    x_size = mbedtls_mpi_size( &ctx_srv.P );
    ctx_cli.len = x_size;
    ctx_srv.len = x_size;

    /*
     * Generate Public Keys
     */
    TEST_ASSERT( mbedtls_dhm_make_public( &ctx_srv, x_size, pub_srv, ctx_srv.len, &rnd_true_rand, &rnd_info_srv ) == 0 );
    TEST_ASSERT( mbedtls_dhm_make_public( &ctx_cli, x_size, pub_cli, ctx_cli.len, &rnd_true_rand, &rnd_info_cli ) == 0 );

    TEST_ASSERT( mbedtls_dhm_read_public( &ctx_srv, pub_cli, ctx_cli.len ) == 0 );
    TEST_ASSERT( mbedtls_dhm_read_public( &ctx_cli, pub_srv, ctx_srv.len ) == 0 );

    /*
     * Compute secrets
     */
    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_srv, sec_srv, sizeof( sec_srv ), &sec_srv_len, &rnd_true_rand, &rnd_info_srv ) == 0 );
    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_cli, sec_cli, sizeof( sec_cli ), &sec_cli_len, &rnd_true_rand, &rnd_info_cli ) == 0 );

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

