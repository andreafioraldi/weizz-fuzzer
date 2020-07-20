/*
   weizz - fuzzer header
   ---------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _WEIZZ_SHARED_H_
#define _WEIZZ_SHARED_H_

#define _GNU_SOURCE

#include "config.h"

/*
#define WTYPE_INS 0
#define WTYPE_RTN 1

typedef struct {

  u64 v0;
  u64 v1;

} cmp_val_t;

struct cmp_header {

  unsigned target_cnt : 16;
  unsigned next_cnt : 16;

  unsigned prev_to_target : MAP_SIZE_POW2;
  unsigned prev_to_next : MAP_SIZE_POW2;

  unsigned counter : 16;
  unsigned cmp_id : 16;

  unsigned type : 1;

  unsigned long reserved : (sizeof(cmp_val_t) * 8 - 2 * MAP_SIZE_POW2 - 65);

} __attribute__((packed));

typedef struct cmp_header cmp_header_t;

#define WMAP_BYTES (WMAP_SIZE * sizeof(cmp_val_t))
#define HEADERIFY(v) ((cmp_header_t *)(v))

*/

#define CMP_MAP_W 65536
#define CMP_MAP_H 256

#define SHAPE_BYTES(x) (x + 1)

#define CMP_TYPE_INS 0
#define CMP_TYPE_RTN 1

struct cmp_header {

  unsigned hits : 20;

  unsigned cnt : 20;
  unsigned id : 16;

  unsigned shape : 5;  // from 0 to 31
  unsigned type : 1;

} __attribute__((packed));

struct cmp_operands {

  u64 v0;
  u64 v1;

};

struct cmpfn_operands {

  u8 v0[32];
  u8 v1[32];

};

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};

#endif
