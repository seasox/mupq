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

#define MAX_WLIST_SIZE (T > D ? T : D)

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
    // TODO: send fault ready trigger here (maybe start sequence idk)
    // TODO: wait N seconds
    a64[i] = val;  // fault here!
    // TODO: send r4, r5 here
    // TODO: send fault window end sequence
  }
}
// TODO print sk to serial in main
