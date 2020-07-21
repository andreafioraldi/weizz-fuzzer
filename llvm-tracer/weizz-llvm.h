#ifndef _WEIZZ_LLVM_H
#define _WEIZZ_LLVM_H

#include "../include/weizz-shared.h"
#include "../include/config.h"

#define PERSISTENT_DEFAULT_MAX_CNT 10000

#define FORKSRV_FD 198
#define TSL_FD (FORKSRV_FD - 1)

#define STR_LOG_SIZE 32

#define SHADOW_BK_SIZE 1024

struct str_call_args {
  uint64_t arg0[4];
  uint64_t arg1[4];
};

struct shadow_item {
  uint16_t addr;
  struct str_call_args* args;
};

typedef struct shadow_item shadow_heavy_t;
typedef uint16_t shadow_light_t;

struct shadow_heavy_block {

  int16_t index;
  shadow_heavy_t buf[SHADOW_BK_SIZE];
  
  struct shadow_heavy_block* next;
};

struct shadow_light_block {

  int16_t index;
  shadow_light_t buf[SHADOW_BK_SIZE];
  
  struct shadow_light_block* next;
};

typedef void shadow_stack_block;

extern __thread shadow_stack_block* shadow_stack; // never NULL
extern __thread uint16_t shadow_hash;

/* Define a total order of cmps */
extern __thread size_t cmp_counter;

extern __thread struct str_call_args last_str_args;
extern __thread uintptr_t last_str_valid_addr;

extern struct cmp_map* heavy_map;

extern uint8_t* light_map;

extern uint8_t* cmp_patch_map;

extern unsigned int weizz_forksrv_pid;
extern uint8_t weizz_fork_child;

extern int ctx_sensitive;
extern int enable_cmp_patching;

#endif
