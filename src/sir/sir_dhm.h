#ifndef SIR_DHM_H
#define SIR_DHM_H

#include <stdint.h>
#include "crypto/include/mbedtls/dhm.h"

typedef enum {
  DHM_SUCCESS = 0, 
  DHM_FAILURE = 1
} dhm_api_result_t;

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

typedef struct {
  mbedtls_dhm_context mbedtls_ctx; /* mbedtls maintains all DHM state in this data structure */
  rnd_pseudo_info rnd_info;        /* random number generator state */
  uint8_t public_component[1000];  /* contains P, G, and G^X mod P (secret X) */
  uint8_t remote_component[1000];  /* contains P, G, and G^Y mod P (secret Y) */
  uint8_t secret_component[384];   /* secret computed using G^X mod P and G^Y mod P */ 
} sir_dhm_context_t;

/** NOTES:
 *     - Caller must allocate the sir_dhm_context_t struct.
 *     - Caller must pass that struct to each API call declared below.
 */

/**
 * \brief                        Generate P, G, and G^X mod P. 
 *
 * \param sir_dhm_context        caller-allocated DHM context struct
 *
 * \return                       DHM_SUCCESS or DHM_FAILURE
 */
dhm_api_result_t dhm_make_public_params(sir_dhm_context_t *);

/**
 * \brief                        Upon reciept of G^Y mod P from remote, 
 *                               compute the DHM secret (of 384 bytes).
 *
 * \param sir_dhm_context        caller-allocated DHM context struct
 *
 * \return                       DHM_SUCCESS or DHM_FAILURE
 */
dhm_api_result_t dhm_compute_secret(sir_dhm_context_t *sir_dhm_context);

#endif /* SIR_DHM_H */
