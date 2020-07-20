/*
   weizz - global variables
   ------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "weizz.h"

u8 checksums_info[WMAP_WIDTH];

//u8 cmp_tag_rates[WMAP_WIDTH];

u8 must_getdeps_asap;

double max_tags_coverage = 0.0;
u32    tags_ntypes_avg;
u32    tags_ntypes_count;
u32    global_max_counter;

u8 surgical_use_derived_tags = 1;
u8 dont_save_interesting;

u64 getdeps_size_limit;

u32 initial_testcases_num;

struct pass_info pass_stats[MAP_SIZE];

u16 tags_counters[WMAP_WIDTH] = { [0 ... (WMAP_WIDTH-1)] = -1 };

struct crash_qentry *crashes_queue;

u8 *in_dir, *out_file, *out_dir, *sync_dir, *sync_id, *use_banner, *in_bitmap,
    *target_path, *orig_cmdline;

char **heavy_argv, **light_argv;
char * file_extension;

char * heavy_binary;

u32 exec_tmout = EXEC_TIMEOUT;
u32 hang_tmout = EXEC_TIMEOUT;

u64 mem_limit = MEM_LIMIT;

u32 stats_update_freq = 1;

u8 skip_deterministic, force_deterministic, use_splicing, score_changed,
    kill_signal, resuming_fuzz, timeout_given, not_on_tty, term_too_small,
    uses_asan, crash_mode, in_place_resume, auto_changed, no_cpu_meter_red,
    no_arith, shuffle_queue, bitmap_changed = 1, skip_requested, run_over10m,
                             deferred_mode, fast_cal;

u8 qemu_mode;

s32 out_fd, dev_urandom_fd = -1, dev_null_fd = -1, light_fsrv_ctl_fd,
            light_fsrv_st_fd, heavy_fsrv_ctl_fd, heavy_fsrv_st_fd;

s32 light_forksrv_pid, light_child_pid = -1, out_dir_fd = -1, heavy_forksrv_pid,
                       heavy_child_pid = -1;

u8 *trace_bits;

u8 virgin_bits[MAP_SIZE], virgin_tmout[MAP_SIZE], virgin_crash[MAP_SIZE];

u8 var_bytes[MAP_SIZE];

struct cmp_map *cmp_map;
struct cmp_map orig_cmp_map;

u8 *cmp_patch_map;
u8  cmp_patch_local_map[WMAP_WIDTH];

u8 new_cksum_found, cksum_found, cksum_patched;

s32 light_shm_id, heavy_shm_id, patches_shm_id;

volatile u8 stop_soon, clear_screen = 1, child_timed_out;

u32 queued_paths, queued_variable, queued_at_start, queued_discovered,
    queued_imported, queued_favored, queued_with_cov, pending_not_fuzzed,
    pending_favored, cur_skipped_paths, cur_depth, max_depth, useless_at_start,
    var_byte_count, current_entry, havoc_div = 1;

u32 tg_queued_num, getdeps_fix, getdeps_fix_total, crash_fix, crash_fix_total;
u32 patched_cksums_num, patched_cksums_total_num;

u64 total_crashes, unique_crashes, total_tmouts, unique_tmouts, unique_hangs,
    total_execs, start_time, last_path_time, last_ckunpatch_time,
    last_crash_time, last_hang_time, last_crash_execs, queue_cycle,
    cycles_wo_finds, trim_execs, bytes_trim_in, bytes_trim_out,
    blocks_eff_total, blocks_eff_select;

u32 subseq_tmouts;

u8 *stage_name = "init", *stage_short, *syncing_party;

s32 stage_cur, stage_max;
s32 splicing_with = -1;

u32 master_id, master_max;

u32 syncing_case;

s32 stage_cur_byte, stage_cur_val;

u8 stage_val_type;

u64 stage_finds[32], stage_cycles[32];

u32 rand_cnt;

u64 total_cal_us, total_cal_cycles;

u64 total_bitmap_size, total_bitmap_entries;

s32 cpu_core_count;

#ifdef HAVE_AFFINITY

s32 cpu_aff = -1;

#endif /* HAVE_AFFINITY */

FILE *plot_file;

struct queue_entry *queue, *queue_cur, *queue_top, *q_prev100;

struct queue_entry *tg_queue, *tg_queue_top, *tg_q_prev100;

struct queue_entry *top_rated[MAP_SIZE];

u8 *trace_bits;

u8 virgin_bits[MAP_SIZE], virgin_tmout[MAP_SIZE], virgin_crash[MAP_SIZE],
    virgin_tmp_crash[MAP_SIZE];

struct extra_data *extras;
u32                extras_cnt;

struct extra_data *a_extras;
u32                a_extras_cnt;

u8 *(*post_handler)(u8 *buf, u32 *len);

/* Interesting values, as per config.h */

s8  interesting_8[]  = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

// u32 cmp_id_rates[WMAP_WIDTH];

u16 sorted_cmps[WMAP_WIDTH];
u32 sorted_cmps_len, sorted_cmps_idx;

u32 found_by_ascii;

/*
u8 full_weizz_mode, aggressive_weizz, enable_byte_brute, smart_mode,
    stacking_mutation_mode, enable_locked_havoc, enable_checksum_recovery,
    avoid_getdeps, has_read_ckinfo, avoid_trim, force_bits_getdeps,
    discard_after_getdeps;
*/

u8 full_weizz_mode, aggressive_weizz, enable_byte_brute, smart_mode,
    stacking_mutation_mode, enable_locked_havoc, enable_checksum_recovery,
    avoid_getdeps, has_read_ckinfo, avoid_trim, force_bits_getdeps,
    discard_after_getdeps;
u8 always_test_cmp_data;

u32 tags_havoc_finds;

u32 last_cmp_that_placed_tag;
struct cmp_header cmp_cur_head;
u32 cmp_cur = -1;

s32 cmp_height_cnt, cmp_height_idx, weizz_brute_num, weizz_brute_max,
    cmp_pass_missed, cmp_pass_all;

u32 weizz_pending_favored;

u8 *already_bruted_bits;
u8  weizz_fuzz_found;

/* if weizz_deps[idx] != 0 then cmp idx has some bit deps */
u8 **weizz_deps[WMAP_WIDTH];

