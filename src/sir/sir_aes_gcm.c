#include "rand/drng.h"
#include "sir_aes_gcm.h"

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


#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif /* defined(MBEDTLS_GCM_C) */
#endif /* defined(MBEDTLS_AES_C) */


#include "string/libstring.h"

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

#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_GCM_C)

#define TEST_ASSERT( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            goto exit;                              \
        }                                           \
    } while( 0 )

/* Contract:
 *  in_key points to a buffer of 256 bits
 *  in_cleartext points to a buffer of 1024 bits
 *  in_iv points to a buffer of 128 bits 
 *  out_tag points to a buffer of 128 bits
 *  out_ciphertext points to a buffer of 1024 bits
 **/
aes_gcm_api_result_t aes_gcm_encrypt_and_tag( uint8_t *in_key, 
                                              uint8_t *in_cleartext, 
                                              uint8_t *in_iv,
                                              uint8_t *out_tag, 
                                              uint8_t *out_ciphertext
                                            ) 
{
    aes_gcm_api_result_t return_value;
    mbedtls_gcm_context ctx;

    return_value = AES_GCM_FAILURE;
    memset(out_ciphertext, 0x00, 128);
    memset(out_tag, 0x00, 16);

    mbedtls_gcm_init( &ctx );
    TEST_ASSERT( mbedtls_gcm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, in_key, 256 ) == 0 );
    TEST_ASSERT( mbedtls_gcm_crypt_and_tag( &ctx, MBEDTLS_GCM_ENCRYPT, 128, in_iv, 16, NULL, 0, in_cleartext, out_ciphertext, 16, out_tag ) == 0 );
    return_value = AES_GCM_SUCCESS;

exit:
    mbedtls_gcm_free( &ctx );
    return return_value;
}

/* Contract:
 *  in_key points to a buffer of 256 bits
 *  in_ciphertext points to a buffer of 1024 bits
 *  in_iv points to a buffer of 128 bits 
 *  in_tag points to a buffer of 128 bits
 *  out_cleartext points to a buffer of 1024 bits
 **/

aes_gcm_api_result_t aes_gcm_decrypt_and_verify( uint8_t *in_key, 
                                                 uint8_t *in_ciphertext, 
                                                 uint8_t *in_iv, 
                                                 uint8_t* in_tag, 
                                                 uint8_t* out_cleartext )
{
    aes_gcm_api_result_t return_value;
    mbedtls_gcm_context ctx;

    return_value = AES_GCM_FAILURE;
    memset(out_cleartext, 0x00, 128);

    mbedtls_gcm_init( &ctx );
    TEST_ASSERT( mbedtls_gcm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, in_key, 256 ) == 0 );
    TEST_ASSERT( mbedtls_gcm_auth_decrypt( &ctx, 128, in_iv, 16, NULL, 0, in_tag, 16, 
                                           in_ciphertext, out_cleartext ) == 0 );
    return_value = AES_GCM_SUCCESS;

exit:
    mbedtls_gcm_free( &ctx );
    return return_value;
}


#endif //MBEDTLS_GCM_C
#endif //MBEDTLS_AES_C
