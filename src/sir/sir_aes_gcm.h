#ifndef SIR_AES_GCM_H
#define SIR_AES_GCM_H

typedef enum {AES_GCM_SUCCESS = 0, AES_GCM_FAILURE = 1} aes_gcm_api_result_t;

/*@ assigns out_tag[0..15], out_ciphertext[0..127];
 */
aes_gcm_api_result_t aes_gcm_encrypt_and_tag( uint8_t *in_key,
                                              uint8_t *in_cleartext,
                                              uint8_t *in_iv,
                                              uint8_t *out_tag,
                                              uint8_t *out_ciphertext
                                            );

/*@ requires \valid(out_cleartext+ (0..127));
    assigns out_cleartext[0..127];
 */
aes_gcm_api_result_t aes_gcm_decrypt_and_verify( uint8_t *in_key, 
                                                 uint8_t *in_ciphertext, 
                                                 uint8_t *in_iv, 
                                                 uint8_t* in_tag, 
                                                 uint8_t* out_cleartext );

#endif /* SIR_AES_GCM_H */
