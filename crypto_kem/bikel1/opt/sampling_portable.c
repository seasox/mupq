/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * Modification: 2021 Ming-Shing Chen, Tung Chou, and Markus Krausz
 *
 */

#include <assert.h>

#include "sampling.h"
#include "hal.h"

#include <libopencm3/stm32/gpio.h>

#define MAX_WLIST_SIZE (T > D ? T : D)

extern void fault_window_start(void);
extern void fault_window_end(void);
extern void delay_some_time(void);
extern void send_r4_r5(void);


static int clk_state = 1;

static void wait_falling() {
    while (true) {
        const int next = gpio_get(GPIOB, GPIO3);
        if (clk_state && !next) {
            clk_state = next;
            break;
        }
        clk_state = next;
    }
}

inline void gpio_set_bit(uint32_t gpioport, uint16_t gpios, uint8_t value) {
  value ? gpio_set(gpioport, gpios) : gpio_clear(gpioport, gpios);
}

void _transfer(const uint8_t *ptr, uint32_t num_bytes) {
    for (uint32_t i = 0; i < num_bytes; i++) {
        const uint8_t value = ptr[i];
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, (value >> 7) & 0x01);
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, (value >> 6) & 0x01);
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, (value >> 5) & 0x01);
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, (value >> 4) & 0x01);
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, (value >> 3) & 0x01);
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, (value >> 2) & 0x01);
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, (value >> 1) & 0x01);
        wait_falling();
        gpio_set_bit(GPIOB, GPIO5, value & 0x01);
    }
}

void secure_set_bits(OUT pad_r_t *   r,
                     IN const size_t first_pos,
                     IN const idx_t *wlist,
                     IN const size_t w_size)
{
  assert(w_size <= MAX_WLIST_SIZE);

  // Ideally we would like to cast r.val but it is not guaranteed to be aligned
  // as the entire pad_r_t structure. Thus, we assert that the position of val
  // is at the beginning of r.
  bike_static_assert(offsetof(pad_r_t, val) == 0, val_wrong_pos_in_pad_r_t);
  // maybe restrict?
  uint64_t *a64 = (uint64_t *)r;
  uint64_t  val, mask;

  // The size of wlist can be either D or T. So, we set it to max(D, T)
  uint32_t pos_qw[MAX_WLIST_SIZE];
  uint64_t pos_bit[MAX_WLIST_SIZE];

  // Identify the QW position of every value, and the bit position inside this QW.
  for(size_t i = 0; i < w_size; i++) {
    int32_t w  = wlist[i] - first_pos;
    pos_qw[i]  = w >> 6;
    pos_bit[i] = BIT(w & MASK(6));
  }

  // Fill each QW in constant time
  for(size_t i = 0; i < (sizeof(*r) / sizeof(uint64_t)); i++) {
    val = 0;
    for(size_t j = 0; j < w_size; j++) {
      mask = (-1ULL) + (!secure_cmp32(pos_qw[j], i));
      // On a 32 bit DUT, rx and ry contain the 64 bits (val) that contain the new key part 
      val |= (pos_bit[j] & mask);
    }
    fault_window_start(); // send fault ready trigger
    // if MOSI PIN is high, delay. Else, immediately send fault window end
    if(gpio_get(GPIOB, GPIO4)) {
      // wait N seconds
      delay_some_time();
    }
    fault_window_end(); // send fault window end sequence
    // Declared in fault_util.S which sends r4 and r5 via GPIO serial.
    send_r4_r5();
    // The partial key is written back to the stack
    a64[i] = val;
  }
}
