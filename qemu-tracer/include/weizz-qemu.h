#ifndef _WEIZZ_DEF_H
#define _WEIZZ_DEF_H

#include "qemu.h"
#include "tcg.h"

#include "../../include/weizz-shared.h"

#define PERSISTENT_DEFAULT_MAX_CNT 10000

#define FORKSRV_FD 198
#define TSL_FD (FORKSRV_FD - 1)

#define STR_LOG_SIZE 32

/* Define a total order of cmps */
extern __thread size_t cmp_counter;

extern __thread uintptr_t shadow_hash;

extern struct cmp_map* heavy_map;
extern uint8_t* light_map;
extern uint8_t* cmp_patch_map;

extern int enable_cmp_patching;
extern target_ulong weizz_target_cmp;

extern abi_ulong weizz_entry_point,
                 weizz_start_code,
                 weizz_end_code,
                 weizz_main_elf_start,
                 weizz_main_elf_end,
                 weizz_tgt_lib_start,
                 weizz_tgt_lib_end,
                 weizz_start_tgt_lib_code,
                 weizz_end_tgt_lib_code;

extern unsigned int weizz_forksrv_pid;
extern uint8_t weizz_fork_child;

extern int is_heavy;
extern int ctx_sensitive;

extern __thread abi_ulong prev_loc;

extern abi_ulong     weizz_persistent_addr, weizz_persistent_ret_addr;
extern unsigned int  weizz_persistent_cnt;
extern unsigned char is_persistent;
extern target_long   persistent_stack_offset;

void tcg_gen_weizz_callN(void *func, TCGTemp *ret, int nargs, TCGTemp **args);

void weizz_gen_trace(target_ulong pc);

void weizz_persistent_loop();

#define ADDR_IS_IN_BOUND(a) \
  ( ((a) >= weizz_start_code && (a) < weizz_end_code) || \
  ((a) >= weizz_start_tgt_lib_code && (a) < weizz_end_tgt_lib_code) )

#endif
