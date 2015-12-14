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


#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif /* defined(MBEDTLS_GCM_C) */
#endif /* defined(MBEDTLS_AES_C) */


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
void aes_gcm_encrypt_and_tag( uint8_t *in_key, 
                              uint8_t *in_cleartext, 
                              uint8_t *in_iv,
                              uint8_t *out_tag, 
                              uint8_t *out_ciphertext
                            ) 
{
    mbedtls_gcm_context ctx;

    memset(out_ciphertext, 0x00, 128);
    memset(out_tag, 0x00, 16);

    mbedtls_gcm_init( &ctx );
    TEST_ASSERT( mbedtls_gcm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, in_key, 256 ) == 0 );
    TEST_ASSERT( mbedtls_gcm_crypt_and_tag( &ctx, MBEDTLS_GCM_ENCRYPT, 128, in_iv, 16, NULL, 0, in_cleartext, out_ciphertext, 16, out_tag ) == 0 );

exit:
    mbedtls_gcm_free( &ctx );
}

/*
void gcm_encrypt_and_tag( int cipher_id,
                          char *hex_key_string, char *hex_src_string,
                          char *hex_iv_string, char *hex_add_string,
                          char *hex_dst_string, int tag_len_bits,
                          char *hex_tag_string, int  init_result )
{
    unsigned char key_str[128];
    unsigned char src_str[128];
    unsigned char dst_str[257];
    unsigned char iv_str[128];
    unsigned char add_str[128];
    unsigned char tag_str[128];
    unsigned char output[128];
    unsigned char tag_output[16];
    mbedtls_gcm_context ctx;
    unsigned int key_len;
    size_t pt_len, iv_len, add_len, tag_len = tag_len_bits / 8;

    mbedtls_gcm_init( &ctx );

    memset(key_str, 0x00, 128);
    memset(src_str, 0x00, 128);
    memset(dst_str, 0x00, 257);
    memset(iv_str, 0x00, 128);
    memset(add_str, 0x00, 128);
    memset(tag_str, 0x00, 128);
    memset(output, 0x00, 128);
    memset(tag_output, 0x00, 16);

    key_len = unhexify( key_str, hex_key_string );
    pt_len = unhexify( src_str, hex_src_string );
    iv_len = unhexify( iv_str, hex_iv_string );
    add_len = unhexify( add_str, hex_add_string );

    TEST_ASSERT( mbedtls_gcm_setkey( &ctx, cipher_id, key_str, key_len * 8 ) == init_result );
    if( init_result == 0 )
    {
        TEST_ASSERT( mbedtls_gcm_crypt_and_tag( &ctx, MBEDTLS_GCM_ENCRYPT, pt_len, iv_str, iv_len, add_str, add_len, src_str, output, tag_len, tag_output ) == 0 );
        hexify( dst_str, output, pt_len );
        hexify( tag_str, tag_output, tag_len );

        TEST_ASSERT( strcmp( (char *) dst_str, hex_dst_string ) == 0 );
        TEST_ASSERT( strcmp( (char *) tag_str, hex_tag_string ) == 0 );
    }

exit:
    mbedtls_gcm_free( &ctx );
}
*/

/* Contract:
 *  in_key points to a buffer of 256 bits
 *  in_ciphertext points to a buffer of 1024 bits
 *  in_iv points to a buffer of 128 bits 
 *  in_tag points to a buffer of 128 bits
 *  out_cleartext points to a buffer of 1024 bits
 **/

void aes_gcm_decrypt_and_verify( uint8_t *in_key, 
                                 uint8_t *in_ciphertext, 
                                 uint8_t *in_iv, 
                                 uint8_t* in_tag, 
                                 uint8_t* out_cleartext)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init( &ctx );

    memset(out_cleartext, 0x00, 128);

    TEST_ASSERT( mbedtls_gcm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, in_key, 256 ) == 0 );
    TEST_ASSERT( mbedtls_gcm_auth_decrypt( &ctx, 128, in_iv, 16, NULL, 0, in_tag, 16, 
                                           in_ciphertext, out_cleartext ) == 0 );

exit:
    mbedtls_gcm_free( &ctx );
}

/*
void gcm_decrypt_and_verify( int cipher_id,
                             char *hex_key_string, char *hex_src_string,
                             char *hex_iv_string, char *hex_add_string,
                             int tag_len_bits, char *hex_tag_string,
                             char *pt_result, int init_result )
{
    unsigned char key_str[128];
    unsigned char src_str[128];
    unsigned char dst_str[257];
    unsigned char iv_str[128];
    unsigned char add_str[128];
    unsigned char tag_str[128];
    unsigned char output[128];
    mbedtls_gcm_context ctx;
    unsigned int key_len;
    size_t pt_len, iv_len, add_len, tag_len = tag_len_bits / 8;
    int ret;

    mbedtls_gcm_init( &ctx );

    memset(key_str, 0x00, 128);
    memset(src_str, 0x00, 128);
    memset(dst_str, 0x00, 257);
    memset(iv_str, 0x00, 128);
    memset(add_str, 0x00, 128);
    memset(tag_str, 0x00, 128);
    memset(output, 0x00, 128);

    key_len = unhexify( key_str, hex_key_string );
    pt_len = unhexify( src_str, hex_src_string );
    iv_len = unhexify( iv_str, hex_iv_string );
    add_len = unhexify( add_str, hex_add_string );
    unhexify( tag_str, hex_tag_string );

    TEST_ASSERT( mbedtls_gcm_setkey( &ctx, cipher_id, key_str, key_len * 8 ) == init_result );
    if( init_result == 0 )
    {
        ret = mbedtls_gcm_auth_decrypt( &ctx, pt_len, iv_str, iv_len, add_str, add_len, tag_str, tag_len, src_str, output );

        if( strcmp( "FAIL", pt_result ) == 0 )
        {
            TEST_ASSERT( ret == MBEDTLS_ERR_GCM_AUTH_FAILED );
        }
        else
        {
            TEST_ASSERT( ret == 0 );
            hexify( dst_str, output, pt_len );

            TEST_ASSERT( strcmp( (char *) dst_str, pt_result ) == 0 );
        }
    }

exit:
    mbedtls_gcm_free( &ctx );
}
*/

#endif //MBEDTLS_GCM_C
#endif //MBEDTLS_AES_C
