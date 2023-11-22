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

#ifdef STM32F4
  #define SCK_PIN PB3
  #define MISO_PIN PB5
  #define MOSI_PIN PB4
#endif

extern void fault_window_start(void);
extern void fault_window_end(void);
extern void delay_some_time(void);
extern void send_r10_r11(void);

//#define FAULT_WINDOW_START() asm volatile("bl _fault_window_start\n")

//#define DELAY_SOME_TIME() asm volatile("bl _delay_some_time\n")

//#define SEND_R4_R5() asm volatile("bl _send_r4_r5\n")

//#define FAULT_WINDOW_END() asm volatile("bl fault_window_end\n")

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
      val |= (pos_bit[j] & mask);
    }
    a64[i] = val;  // fault here!
    // if MOSI is high, wait for fault. Otherwise just continue w/ KGen
    if(gpio_get(GPIOB, GPIO4)) {
      // send fault ready trigger
      fault_window_start();
      // wait N seconds
      delay_some_time();
      // send fault window end sequence
      fault_window_end();
      // send r10, r11 here
      send_r10_r11();
    }
  }
}
// TODO print sk to serial in main
