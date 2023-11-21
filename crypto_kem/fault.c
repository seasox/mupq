#include "api.h"
#include "randombytes.h"
#include "hal.h"

#include <stdio.h>
#include <string.h>

#include <libopencm3/stm32/gpio.h>

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


static int test_fault_keygen(void)
{
  unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];

  MUPQ_crypto_kem_keypair(pk, sk);
  hal_send_str(sk);
  return 0;
}

static void gpio_setup(void) {
  gpio_mode_setup(GPIOB, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO5);
}

int main(void)
{
  hal_setup(CLOCK_FAST);
  gpio_setup();

  // marker for automated testing
  hal_send_str("==========================");
  while(1) {
    hal_send_str("RUN");
    test_fault_keygen();
  }
  hal_send_str("#");

  return 0;
}
