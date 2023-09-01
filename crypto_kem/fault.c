#include "api.h"
#include "randombytes.h"
#include "hal.h"

#include <stdio.h>
#include <string.h>

#include "utilities.h"

#define NTESTS 10

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec)

static int is_faulty_key(unsigned char *sk_in) {
  aligned_sk_t *sk = (aligned_sk_t*)sk_in;
  uint32_t h0_weight = r_bits_vector_weight(&sk->bin[0]);
  uint32_t h1_weight = r_bits_vector_weight(&sk->bin[1]);
  if(h0_weight != D && h0_weight == h1_weight) {
    char msg[128];
    snprintf(msg, sizeof(msg), "type-one %lu %lu %u", h0_weight, h1_weight, D);
    hal_send_str(msg);
    return 1;
  }
  if(h0_weight != h1_weight && (h0_weight == D || h1_weight == D)) {
    char msg[128];
    snprintf(msg, sizeof(msg), "type-two %lu %lu %u", h0_weight, h1_weight, D);
    hal_send_str(msg);
    return 1;
  }
  return 0;
}

#define GET_BIT(x, i) ((x>>i)&1)

#define WEAK_KEY_F 7  // TODO how should we choose F?

static int is_weak_key(unsigned char *sk_in) {
  aligned_sk_t *sk = (aligned_sk_t*)sk_in;
#if 0
  uint32_t h0_weight = r_bits_vector_weight(&sk->bin[0]);
  uint32_t h1_weight = r_bits_vector_weight(&sk->bin[1]);
  if(h0_weight != D || h1_weight != D) {
    // this is a faulty key
    return 0;
  }
  int count = 0;
  for(int i = 0; i < R_BITS; ++i) {
    if(GET_BIT(sk->bin[0].val, i)) {
      count++;
    } else {
      count = 0;
    }
    if(count == WEAK_KEY_F) {
      return 1;
    }
  }
#endif
  return 0;
}

static int test_fault_keygen(void)
{
  unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];

  MUPQ_crypto_kem_keypair(pk, sk);
  if(is_faulty_key(sk)) {
    hal_send_str("faulty");
  }
  if(is_weak_key(sk)) {
    hal_send_str("weak");
  }
  return 0;
}

int main(void)
{
  hal_setup(CLOCK_FAST);

  // marker for automated testing
  hal_send_str("==========================");
  while(1) {
    test_fault_keygen();
  }
  hal_send_str("#");

  return 0;
}
