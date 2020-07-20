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

#ifndef _WEIZZ_H_
#define _WEIZZ_H_

//#define TEST_BUILD

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include "alloc-inl.h"
#include "config.h"
#include "debug.h"
#include "hash.h"
#include "types.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#  include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

#include "weizz-shared.h"

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#ifdef __linux__
#  define HAVE_AFFINITY 1
#endif /* __linux__ */

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

/* Bit manipulation macros */

#ifdef __x86_64__
#  define GET_LASTBIT(num) ((num) >> 63)
#  define SET_LASTBIT(num) ((num) | (1ull << 63))
#else
#  define GET_LASTBIT(num) ((num) >> 31)
#  define SET_LASTBIT(num) ((num) | (1 << 31))
#endif

#define GET_BIT(_ar, _b) !!((((u8 *)(_ar))[(_b) >> 3] & (128 >> ((_b)&7))))

#define SET_BIT(_ar, _b)                    \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf  = (_b);                        \
    _arf[(_bf) >> 3] |= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf  = (_b);                        \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)


#define TAG_CMP_IS_LEFT 0x1
#define TAG_CMP_IS_CHECKSUM 0x2
#define TAG_IS_INPUT_TO_STATE 0x4
#define TAG_IS_LEN 0x8
#define TAG_IS_IMPL 0x10

struct tag {

  u16 cmp_id;
  u16 parent;
  u16 counter;
  u16 depends_on;
  u8  flags;

} __attribute__((packed));

struct tags_info {

  u32   ntypes;
  u32   max_counter;
  struct tag tags[];

};

struct extra_data {

  u8 *data;                             /* Dictionary token data            */
  u32 len;                              /* Dictionary token length          */
  u32 hit_cnt;                          /* Use count in the corpus          */

};

struct queue_entry {

  u8 *fname;                            /* File name for the test case      */
  u32 len;                              /* Input length                     */

  u8 cal_failed,                        /* Calibration failed?              */
      trim_done,                        /* Trimmed?                         */
      was_fuzzed,                       /* Had any fuzzing done yet?        */
      passed_det,                       /* Deterministic stages passed?     */
      has_new_cov,                      /* Triggers new coverage?           */
      var_behavior,                     /* Variable behavior?               */
      favored,                          /* Currently favored?               */
      fs_redundant;                     /* Marked as redundant in the fs?   */

  u32 bitmap_size,                      /* Number of bits set in bitmap     */
      exec_cksum;                       /* Checksum of the execution trace  */

  u64 exec_us,                          /* Execution time (us)              */
      handicap,                         /* Number of queue cycles behind    */
      depth;                            /* Path depth                       */

  u8 *trace_mini;                       /* Trace bytes, if kept             */

  u8 *tags_fname;
  u8 *sync_tags_fname;
  u8 *sync_fname;

  struct queue_entry *parent;

  u32 tc_ref;                           /* Trace bytes ref count            */

  /* weizz */
  u32 weizz_favored;

  u8 passed_getdeps;
  u8 use_derived_tags;
  u8 is_invalid;
  u8 must_fix_checksums;
  u8 did_only_getdeps;
  u8 tg_queued;
  u8 fully_colorized;

  double tags_coverage;
  u32    cached_tags_ntypes;                            /* Not always valid */
  u32    cached_max_counter;

  struct queue_entry *tg_next, *tg_next_100;

  struct queue_entry *next,             /* Next element, if any             */
      *next_100;                        /* 100 elements ahead               */

};

struct pass_info {

  u8 failed;
  u8 total;

};

struct crash_qentry {

  u8 *description;
  u8  saved_bits[MAP_SIZE];
  u64 last_crash_time;
  u64 last_crash_execs;
  u8 *mem;
  u32 len;
  u8  kill_signal;

  struct crash_qentry *next;

};

enum {

  /* 00 */ CKTYPE_NO,
  /* 01 */ CKTYPE_NORMAL8,
  /* 02 */ CKTYPE_NORMAL16,
  /* 03 */ CKTYPE_NORMAL32,
  /* 04 */ CKTYPE_NORMAL64,
  /* 05 */ CKTYPE_SWAP16,
  /* 06 */ CKTYPE_SWAP32,
  /* 07 */ CKTYPE_SWAP64,

};

#define CK_IS_LEFT 0x0
#define CK_IS_RIGHT 0x80
#define CK_ARGTYPE_MASK 0x80

#define CK_WARNING 0x40
#define CK_NOT_UNDER_CONTROL 0xff

extern u8 checksums_info[WMAP_WIDTH];

extern u8 cmp_tag_rates[WMAP_WIDTH];

extern u8 must_getdeps_asap;

extern double max_tags_coverage;
extern u32    tags_ntypes_avg;
extern u32    tags_ntypes_count;
extern u32    global_max_counter;

extern u8 surgical_use_derived_tags;
extern u8 dont_save_interesting;

extern u64 getdeps_size_limit;

extern u32 initial_testcases_num;

extern struct pass_info pass_stats[MAP_SIZE];

extern u16 tags_counters[WMAP_WIDTH];

extern struct crash_qentry *crashes_queue;

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

extern u8 *in_dir,                      /* Input directory with test cases  */
    *out_file,                          /* File to fuzz, if any             */
    *out_dir,                           /* Working & output directory       */
    *sync_dir,                          /* Synchronization directory        */
    *sync_id,                           /* Fuzzer ID                        */
    *use_banner,                        /* Display banner                   */
    *in_bitmap,                         /* Input bitmap                     */
    *target_path,                       /* Path to target binary            */
    *orig_cmdline;                      /* Original command line            */

extern char **heavy_argv, **light_argv;
extern char * file_extension;

extern char * heavy_binary;

extern u32 exec_tmout;                  /* Configurable exec timeout (ms)   */
extern u32 hang_tmout;                  /* Timeout used for hang det (ms)   */

extern u64 mem_limit;                   /* Memory cap for child (MB)        */

extern u32 stats_update_freq;           /* Stats update frequency (execs)   */

extern u8 skip_deterministic,           /* Skip deterministic stages?       */
    force_deterministic,                /* Force deterministic stages?      */
    use_splicing,                       /* Recombine input files?           */
    score_changed,                      /* Scoring for favorites changed?   */
    kill_signal,                        /* Signal that killed the child     */
    resuming_fuzz,                      /* Resuming an older fuzzing job?   */
    timeout_given,                      /* Specific timeout given?          */
    not_on_tty,                         /* stdout is not a tty              */
    term_too_small,                     /* terminal dimensions too small    */
    uses_asan,                          /* Target uses ASAN?                */
    crash_mode,                         /* Crash mode! Yeah!                */
    in_place_resume,                    /* Attempt in-place resume?         */
    auto_changed,                       /* Auto-generated tokens changed?   */
    no_cpu_meter_red,                   /* Feng shui on the status screen   */
    no_arith,                           /* Skip most arithmetic ops         */
    shuffle_queue,                      /* Shuffle input queue?             */
    bitmap_changed,                     /* Time to update bitmap?           */
    skip_requested,                     /* Skip request, via SIGUSR1        */
    run_over10m,                        /* Run time over 10 minutes?        */
    deferred_mode,                      /* Deferred forkserver mode?        */
    fast_cal;                           /* Try to calibrate faster?         */

extern u8 qemu_mode;

extern s32 out_fd,                      /* Persistent fd for out_file       */
    dev_urandom_fd,                     /* Persistent fd for /dev/urandom   */
    dev_null_fd,                        /* Persistent fd for /dev/null      */
    light_fsrv_ctl_fd,                  /* Fork server control pipe (write) */
    light_fsrv_st_fd,                   /* Fork server status pipe (read)   */
    heavy_fsrv_ctl_fd,                  /* Fork server control pipe (write) */
    heavy_fsrv_st_fd;                   /* Fork server status pipe (read)   */

extern s32 light_forksrv_pid,           /* PID of the fork server           */
    light_child_pid,                    /* PID of the fuzzed program        */
    out_dir_fd,                         /* FD of the lock file              */
    heavy_forksrv_pid,                  /* PID of the fork server           */
    heavy_child_pid;                    /* PID of the fuzzed program        */

extern u8 *trace_bits;                  /* SHM with instrumentation bitmap  */

extern u8 virgin_bits[MAP_SIZE],        /* Regions yet untouched by fuzzing */
    virgin_tmout[MAP_SIZE],             /* Bits we haven't seen in tmouts   */
    virgin_crash[MAP_SIZE],             /* Bits we haven't seen in crashes  */
    virgin_tmp_crash[MAP_SIZE];         /* Bits we haven't seen in crashes  */

extern u8 var_bytes[MAP_SIZE];          /* Bytes that appear to be variable */

extern struct cmp_map *cmp_map;
extern struct cmp_map orig_cmp_map;

extern u8 *cmp_patch_map;
extern u8  cmp_patch_local_map[WMAP_WIDTH];

extern u8 new_cksum_found, cksum_found, cksum_patched;

extern struct tags_info *cmp_cur_patch_tags;

extern s32 light_shm_id, heavy_shm_id,
    patches_shm_id;                     /* ID of the SHM region             */

extern volatile u8 stop_soon,           /* Ctrl-C pressed?                  */
    clear_screen,                       /* Window resized?                  */
    child_timed_out;                    /* Traced process timed out?        */

extern u32 queued_paths,                /* Total number of queued testcases */
    queued_variable,                    /* Testcases with variable behavior */
    queued_at_start,                    /* Total number of initial inputs   */
    queued_discovered,                  /* Items discovered during this run */
    queued_imported,                    /* Items imported via -S            */
    queued_favored,                     /* Paths deemed favorable           */
    queued_with_cov,                    /* Paths with new coverage bytes    */
    pending_not_fuzzed,                 /* Queued but not done yet          */
    pending_favored,                    /* Pending favored paths            */
    cur_skipped_paths,                  /* Abandoned inputs in cur cycle    */
    cur_depth,                          /* Current path depth               */
    max_depth,                          /* Max path depth                   */
    useless_at_start,                   /* Number of useless starting paths */
    var_byte_count,                     /* Bitmap bytes with var behavior   */
    current_entry,                      /* Current queue entry ID           */
    havoc_div;                          /* Cycle count divisor for havoc    */

extern u32 tg_queued_num, getdeps_fix, getdeps_fix_total, crash_fix,
    crash_fix_total;
extern u32 patched_cksums_num, patched_cksums_total_num;

extern u64 total_crashes,               /* Total number of crashes          */
    unique_crashes,                     /* Crashes with unique signatures   */
    total_tmouts,                       /* Total number of timeouts         */
    unique_tmouts,                      /* Timeouts with unique signatures  */
    unique_hangs,                       /* Hangs with unique signatures     */
    total_execs,                        /* Total execve() calls             */
    start_time,                         /* Unix start time (ms)             */
    last_path_time,                     /* Time for most recent path (ms)   */
    last_crash_time,                    /* Time for most recent crash (ms)  */
    last_hang_time,                     /* Time for most recent hang (ms)   */
    last_crash_execs,                   /* Exec counter at last crash       */
    last_ckunpatch_time, queue_cycle,   /* Queue round counter              */
    cycles_wo_finds,                    /* Cycles without any new paths     */
    trim_execs,                         /* Execs done to trim input files   */
    bytes_trim_in,                      /* Bytes coming into the trimmer    */
    bytes_trim_out,                     /* Bytes coming outa the trimmer    */
    blocks_eff_total,                   /* Blocks subject to effector maps  */
    blocks_eff_select;                  /* Blocks selected as fuzzable      */

extern u32 subseq_tmouts;               /* Number of timeouts in a row      */

extern u8 *stage_name,                  /* Name of the current fuzz stage   */
    *stage_short,                       /* Short stage name                 */
    *syncing_party;                     /* Currently syncing with...        */

extern s32 stage_cur, stage_max;        /* Stage progression                */
extern s32 splicing_with;               /* Splicing with which test case?   */

extern u32 master_id, master_max;       /* Master instance job splitting    */

extern u32 syncing_case;                /* Syncing with case #...           */

extern s32 stage_cur_byte,              /* Byte offset of current stage op  */
    stage_cur_val;                      /* Value used for stage op          */

extern u8 stage_val_type;               /* Value type (STAGE_VAL_*)         */

extern u64 stage_finds[32],             /* Patterns found per fuzz stage    */
    stage_cycles[32];                   /* Execs per fuzz stage             */

extern u32 rand_cnt;                    /* Random number counter            */

extern u64 total_cal_us,                /* Total calibration time (us)      */
    total_cal_cycles;                   /* Total calibration cycles         */

extern u64 total_bitmap_size,           /* Total bit count for all bitmaps  */
    total_bitmap_entries;               /* Number of bitmaps counted        */

extern s32 cpu_core_count;              /* CPU core count                   */

#ifdef HAVE_AFFINITY

extern s32 cpu_aff;                     /* Selected CPU core                */

#endif /* HAVE_AFFINITY */

extern FILE *plot_file;                 /* Gnuplot output file              */

extern struct queue_entry *queue,       /* Fuzzing queue (linked list)      */
    *queue_cur,                         /* Current offset within the queue  */
    *queue_top,                         /* Top of the list                  */
    *q_prev100;                         /* Previous 100 marker              */

extern struct queue_entry *tg_queue, *tg_queue_top, *tg_q_prev100;

extern struct queue_entry
    *top_rated[MAP_SIZE];               /* Top entries for bitmap bytes     */

extern struct extra_data *extras;       /* Extra tokens to fuzz with        */
extern u32                extras_cnt;   /* Total number of tokens read      */

extern struct extra_data *a_extras;     /* Automatically selected extras    */
extern u32                a_extras_cnt; /* Total number of tokens available */

extern u8 *(*post_handler)(u8 *buf, u32 *len);

/* Interesting values, as per config.h */

extern s8  interesting_8[INTERESTING_8_LEN];
extern s16 interesting_16[INTERESTING_8_LEN + INTERESTING_16_LEN];
extern s32
    interesting_32[INTERESTING_8_LEN + INTERESTING_16_LEN + INTERESTING_32_LEN];

extern u32 cmp_id_rates[WMAP_WIDTH];

extern u16 sorted_cmps[WMAP_WIDTH];
extern u32 sorted_cmps_len, sorted_cmps_idx;

extern u32 found_by_ascii;

extern u8 full_weizz_mode, aggressive_weizz, enable_byte_brute, smart_mode,
    stacking_mutation_mode, enable_locked_havoc, enable_checksum_recovery,
    avoid_getdeps, has_read_ckinfo, avoid_trim, force_bits_getdeps,
    discard_after_getdeps;
extern u8 always_test_cmp_data;

extern u32 tags_havoc_finds;

extern u32 last_cmp_that_placed_tag;
//extern struct cmp_header cmp_cur_head;
//extern u32 cmp_cur;

extern s32 cmp_height_cnt, cmp_height_idx, weizz_brute_num, weizz_brute_max,
    cmp_pass_missed, cmp_pass_all;

extern u32 weizz_pending_favored;

extern u8 *already_bruted_bits;
extern u8  weizz_fuzz_found;

/* if weizz_deps[idx] != 0 then cmp idx has some bit deps */
extern u8 **weizz_deps[WMAP_WIDTH];

#define V0_DEPS_SET(i, j, b)                                       \
  do {                                                             \
                                                                   \
    if (!weizz_deps[i])                                            \
      weizz_deps[i] = ck_alloc(sizeof(u8 **) * CMP_MAP_H); \
    if (!weizz_deps[i][(j)])                                       \
      weizz_deps[i][(j)] = ck_alloc(4 * (len >> 3) + 4);           \
    weizz_deps[i][(j)][((b)*4) >> 3] |= (128 >> (((b)*4) & 7));    \
                                                                   \
  } while (0)

#define IMPL_V0_DEPS_SET(i, j, b)                                       \
  do {                                                             \
                                                                   \
    if (!weizz_deps[i])                                            \
      weizz_deps[i] = ck_alloc(sizeof(u8 **) * CMP_MAP_H); \
    if (!weizz_deps[i][(j)])                                       \
      weizz_deps[i][(j)] = ck_alloc(4 * (len >> 3) + 4);           \
    weizz_deps[i][(j)][((b)*4+1) >> 3] |= (128 >> (((b)*4+1) & 7));    \
                                                                   \
  } while (0)

#define V1_DEPS_SET(i, j, b)                                            \
  do {                                                                  \
                                                                        \
    if (!weizz_deps[i])                                                 \
      weizz_deps[i] = ck_alloc(sizeof(u8 **) * CMP_MAP_H);      \
    if (!weizz_deps[i][(j)])                                            \
      weizz_deps[i][(j)] = ck_alloc(4 * (len >> 3) + 4);                \
    weizz_deps[i][(j)][((b)*4+2) >> 3] |= (128 >> (((b)*4+2) & 7)); \
                                                                        \
  } while (0)

#define IMPL_V1_DEPS_SET(i, j, b)                                            \
  do {                                                                  \
                                                                        \
    if (!weizz_deps[i])                                                 \
      weizz_deps[i] = ck_alloc(sizeof(u8 **) * CMP_MAP_H);      \
    if (!weizz_deps[i][(j)])                                            \
      weizz_deps[i][(j)] = ck_alloc(4 * (len >> 3) + 4);                \
    weizz_deps[i][(j)][((b)*4+3) >> 3] |= (128 >> (((b)*4+3) & 7)); \
                                                                        \
  } while (0)

#define DEPS_GET(i, j) weizz_deps[i][(j)]

#define DEPS_EXISTS(i, j) (weizz_deps[i] && weizz_deps[i][(j)])

#define V0_HASDEP(deps, b) GET_BIT(deps, (b)*4)
#define IMPL_V0_HASDEP(deps, b) GET_BIT(deps, (b)*4+1)
#define V1_HASDEP(deps, b) GET_BIT(deps, (b)*4+2)
#define IMPL_V1_HASDEP(deps, b) GET_BIT(deps, (b)*4+3)

#define ANY_V0_HASDEP(deps, b) (V0_HASDEP(deps, b) || IMPL_V0_HASDEP(deps, b))
#define ANY_V1_HASDEP(deps, b) (V1_HASDEP(deps, b) || IMPL_V1_HASDEP(deps, b))

/* Stage value types */

enum {

  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE

};

/* Execution status fault codes */

enum {

  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS

};

/* Fuzzing stages */

enum {

  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE,
  /* 17 */ STAGE_GETDEPS,
  /* 18 */ STAGE_COLORIZATION,
  /* 19 */ STAGE_ITS,
  /* 20 */ STAGE_SAVE_TEMPS,
  /* 21 */ STAGE_LOCKED_HAVOC,
  /* 22 */ STAGE_TAGS_HAVOC,
  /* 23 */ STAGE_TAGS_SPLICE,

};

/* init.c */

void check_if_tty(void);
void fix_up_sync(void);
void bind_to_free_cpu(void);
void check_crash_handling(void);
void check_cpu_governor(void);
void setup_post(void);
void setup_shm(void);
void setup_dirs_fds(void);
void read_testcases(void);
void pivot_inputs(void);
void find_timeout(void);
void setup_stdio_file(void);
void check_binary(u8 *fname);
u32  find_start_position(void);

/* stats.c */

void fix_up_banner(u8 *name);
void show_stats(void);
void show_init_stats(void);
void write_stats_file(double bitmap_cvg, double stability, double eps);

/* bitmap.c */

void read_bitmap(u8 *fname);
void write_bitmap(void);
void init_count_class16(void);
u32  has_new_bits(u8 *virgin_map);
void update_bitmap_score(struct queue_entry *q);
u8   save_if_interesting(void *mem, u32 len, u8 fault);
u32  calculate_score(struct queue_entry *q);
#ifdef __x86_64__
void classify_counts(u64 *mem);
#else
void classify_counts(u32 *mem);
#endif
u32 count_bits(u8 *mem);
u32 count_bytes(u8 *mem);
u32 count_non_255_bytes(u8 *mem);

/* extras.c */

void load_auto(void);
void load_extras(u8 *dir);
void save_auto(void);
void maybe_add_auto(u8 *mem, u32 len);
void destroy_extras(void);

/* queue.c */

void mark_as_variable(struct queue_entry *q);
void cull_queue(void);
void add_to_queue(u8 *fname, u32 len, u8 passed_det);
void add_to_tg_queue(struct queue_entry *q);
void destroy_queue(void);
void mark_as_det_done(struct queue_entry *q);
void sync_fuzzers();
void update_synced(struct queue_entry *q);

/* utils.c */

u8 *   DI(u64 val);
u8 *   DF(double val);
u8 *   DMS(u64 val);
u8 *   DTD(u64 cur_ms, u64 event_ms);
u64    get_cur_time(void);
u64    get_cur_time_us(void);
void   shuffle_ptrs(void **ptrs, u32 cnt);
void   locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last);
u32    choose_block_len(u32 limit);
void   write_to_testcase(void *mem, u32 len);
void   link_or_copy(u8 *old_path, u8 *new_path);
u8     delete_files(u8 *path, u8 *prefix);
double get_runnable_processes(void);
void   get_core_count(void);

/* run.c */

void perform_dry_run();
void init_light_forkserver(char **argv);
void init_heavy_forkserver(char **argv);
u8   run_light_target(u32 timeout);
u8   run_heavy_target(u32 timeout, u32 target_branch);
u8   common_light_fuzz_stuff(u8 *out_buf, u32 len);
u8   common_heavy_fuzz_stuff(u8 *out_buf, u32 len);

/* pre_fuzz.c */

u8 trim_case(struct queue_entry *q, u8 *in_buf);
u8 calibrate_case(struct queue_entry *q, u8 *use_mem, u32 handicap,
                  u8 from_queue);

/* fuzz_one.c */

u8 fuzz_one();

/* get_deps.c */

void         read_pass_stats(u8 *fname);
u8 weizz_first_stage(u32 perf_score, u8 *buf, u32 len);
struct tags_info* produce_checksums_tags(u8* buf, u32 len);

/* signals.c */

void setup_signal_handlers(void);

/* tags.c */

u8 higher_order_fuzzing(struct tags_info **p_ti, s32 *temp_len, u8 **buf,
                        s32 alloc_size);

/* checksums.c */

void read_patch_map(u8 *fname);
void update_checkusms_local_map();
void write_patch_map(void);
u8   fix_checksums(u32 hash_cksum, struct tags_info *ti, u8 *out_buf, s32 len,
                   u32 *ck_count, u8 must_crash);
void crashes_reconciliation(void);

/* INLINE ROUTINES */

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}

static inline int locked_open(const char *path, int flags) {

  int fd = open(path, flags);
  if (fd < 0) return fd;

  if (flock(fd, LOCK_EX) < 0) return -1;

  return fd;

}

static inline int locked_open_mode(const char *path, int flags, mode_t mode) {

  int fd = open(path, flags, mode);
  if (fd < 0) return fd;

  if (flock(fd, LOCK_EX) < 0) return -1;

  return fd;

}

#endif

