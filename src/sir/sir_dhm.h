#ifndef SIR_DHM_H
#define SIR_DHM_H

typedef enum {SUCCESS = 0, FAILURE = 1} result_t;

typedef struct {
  result_t outcome;
  uint8_t *dhm_pub;
  uint64_t dhm_pub_size;
} dhm_make_public_params_ret_t;

typedef struct {
  result_t outcome;
  uint8_t *dhm_sec;
  uint64_t dhm_sec_size;
} dhm_compute_secret_ret_t;


result_t dhm_test();
dhm_make_public_params_ret_t dhm_make_public_params();
dhm_compute_secret_ret_t dhm_compute_secret();

#endif /* SIR_DHM_H */
