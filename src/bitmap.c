/*
   weizz - operations on trace_bits
   --------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "weizz.h"

u32 consecutive_different_crashes;
u64 last_crash_enque_exec;

u32 consecutive_different_hangs;
u64 last_hang_exec;

/* Read bitmap from file. This is for the -B option again. */

void read_bitmap(u8 *fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);

}

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(void) {

  u8 *fname;
  s32 fd;

  if (!bitmap_changed) return;
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd    = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);

}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

u32 has_new_bits(u8 *virgin_map) {

#ifdef __x86_64__

  u64 *current = (u64 *)trace_bits;
  u64 *virgin  = (u64 *)virgin_map;

  u32 i = (MAP_SIZE >> 3);

#else

  u32 *current = (u32 *)trace_bits;
  u32 *virgin  = (u32 *)virgin_map;

  u32 i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u32 ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8 *cur = (u8 *)current;
        u8 *vir = (u8 *)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
          ret = 2;
        else
          ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
          ret = 2;
        else
          ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

  if (ret) return ret;

  return ret;

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {

      ret += 32;
      continue;

    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}

#define FF(_b) (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

#ifdef __x86_64__

static void simplify_trace(u64 *mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else

      *mem = 0x0101010101010101ULL;

    mem++;

  }

}

#else

static void simplify_trace(u32 *mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else

      *mem = 0x01010101;

    mem++;

  }

}

#endif /* ^__x86_64__ */

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

    [0]           = 0,
    [1]           = 1,
    [2]           = 2,
    [3]           = 4,
    [4 ... 7]     = 8,
    [8 ... 15]    = 16,
    [16 ... 31]   = 32,
    [32 ... 127]  = 64,
    [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++)
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

}

#ifdef __x86_64__

void classify_counts(u64 *mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16 *mem16 = (u16 *)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else

void classify_counts(u32 *mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16 *mem16 = (u16 *)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

void update_bitmap_score(struct queue_entry *q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

      if (top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */

        if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its trace_bits[] if necessary. */

        if (!--top_rated[i]->tc_ref) {

          ck_free(top_rated[i]->trace_mini);
          top_rated[i]->trace_mini = 0;

        }

      }

      /* Insert ourselves as the new winner. */

      top_rated[i] = q;
      q->tc_ref++;

      if (!q->trace_mini) {

        q->trace_mini = ck_alloc(MAP_SIZE >> 3);
        minimize_bits(q->trace_mini, trace_bits);

      }

      score_changed = 1;

    }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8 *describe_op(u8 hnb) {

  static u8 ret[256];

  if (syncing_party) {

    sprintf(ret, "sync:%s,src:%06u,time:%llu", syncing_party, syncing_case,
            (get_cur_time() - start_time));

  } else {

    sprintf(ret, "src:%06u", current_entry);

    if (splicing_with >= 0) sprintf(ret + strlen(ret), "+%06u", splicing_with);

    sprintf(ret + strlen(ret), ",time:%llu", (get_cur_time() - start_time));

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {

      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d",
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "", stage_cur_val);

    } else

      sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);

  }

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}

#endif /* !SIMPLE_FILES */

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

u8 save_if_interesting(void *mem, u32 len, u8 fault) {

  u8 *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  if (fault == crash_mode) {

    /* Keep only if there are new bits in the map, add to queue for
   future fuzzing, etc. */

    hnb = has_new_bits(virgin_bits);

    if (!hnb) {

      if (crash_mode) total_crashes++;
        return 0;

    }

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue(fn, len, 0);

    if (hnb == 2) {

      queue_top->has_new_cov = 1;
      queued_with_cov++;

    }

    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR) FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
     a handful of samples. We use the presence of new bits in the
     hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
     just keep everything. */

      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

#ifdef __x86_64__
      simplify_trace((u64 *)trace_bits);
#else
      simplify_trace((u32 *)trace_bits);
#endif /* ^__x86_64__ */

      if (!has_new_bits(virgin_tmout)) {

        consecutive_different_hangs = 0;
        return keeping;

      }

      unique_tmouts++;

      /* Before saving, we make sure that it's a genuine hang by re-running
     the target with a more generous timeout (unless the default timeout
     is already generous). */

      if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_light_target(hang_tmout);

        /* A corner case that one user reported bumping into: increasing the
     timeout actually uncovers a crash. Make sure we don't discard it if
     so. */

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

        last_hang_exec += 1;

      }

      if (enable_checksum_recovery && cksum_patched &&
          last_hang_exec + 1 == total_execs) {

        ++consecutive_different_hangs;

        if (consecutive_different_hangs == 8) {

          write_to_testcase(mem, len);

          s32 k;
          for (k = 0; k < WMAP_WIDTH; ++k) {

            if (likely(!checksums_info[k] ||
                       checksums_info[k] == CK_NOT_UNDER_CONTROL))
              continue;

            cmp_patch_map[k] = 0;

            u8 new_fault = run_light_target(exec_tmout);

            if (new_fault != FAULT_TMOUT) {

              DBGPRINT(" %x CRASHING NOT UNDER CONTROL\n", k);

              checksums_info[k]      = CK_NOT_UNDER_CONTROL;
              cmp_patch_local_map[k] = 0;

              --patched_cksums_num;
              break;

            } else

              cmp_patch_map[k] = 0xff;

          }

        }

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir, unique_hangs,
                        describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir, unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;

      last_hang_time = get_cur_time();

      last_hang_exec = total_execs;

      break;

    case FAULT_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

#ifdef __x86_64__
      simplify_trace((u64 *)trace_bits);
#else
      simplify_trace((u32 *)trace_bits);
#endif /* ^__x86_64__ */

      /* Fix crash checksums */

      if (enable_checksum_recovery && cksum_patched) {

        if (!has_new_bits(virgin_tmp_crash)) {

          consecutive_different_crashes = 0;
          return keeping;

        }

        if (last_crash_enque_exec + 1 == total_execs) {

          ++consecutive_different_crashes;

          if (consecutive_different_crashes == 8) {

            write_to_testcase(mem, len);

            s32 k;
            for (k = 0; k < WMAP_WIDTH; ++k) {

              if (likely(!checksums_info[k] ||
                         checksums_info[k] == CK_NOT_UNDER_CONTROL))
                continue;

              cmp_patch_map[k] = 0;

              u8 new_fault = run_light_target(exec_tmout);

              if (new_fault != FAULT_CRASH) {

                DBGPRINT(" %x CRASHING NOT UNDER CONTROL\n", k);

                checksums_info[k]      = CK_NOT_UNDER_CONTROL;
                cmp_patch_local_map[k] = 0;

                --patched_cksums_num;
                break;

              } else

                cmp_patch_map[k] = 0xff;

            }

          }

        }

        /* Check if the crash is not a false positive caused by a wrong routine
           parameter interpeted as a valid pointer in heavy-weizz-qemu */

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_light_target(exec_tmout);

        if (new_fault != FAULT_CRASH) return keeping;

        struct crash_qentry *cq = ck_alloc_nozero(sizeof(struct crash_qentry));
        memcpy(cq->saved_bits, trace_bits, MAP_SIZE);
        cq->mem = ck_alloc_nozero(len);
        memcpy(cq->mem, mem, len);
        cq->len = len;

        last_crash_enque_exec = total_execs;

        cq->last_crash_time  = get_cur_time();
        cq->last_crash_execs = total_execs;
        cq->kill_signal      = kill_signal;
        cq->description      = ck_strdup(describe_op(0));

        cq->next      = crashes_queue;
        crashes_queue = cq;

        return keeping;

      }

      if (!has_new_bits(virgin_crash)) return keeping;

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      unique_crashes++;

      last_crash_time  = get_cur_time();
      last_crash_execs = total_execs;

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
   test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

u32 calculate_score(struct queue_entry *q) {

  u32 avg_exec_us     = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score      = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us)
    perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us)
    perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us)
    perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us)
    perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us)
    perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us)
    perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us)
    perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size)
    perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size)
    perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size)
    perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size)
    perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size)
    perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size)
    perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3: break;
    case 4 ... 7: perf_score *= 2; break;
    case 8 ... 13: perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default: perf_score *= 5;

  }

  // POWER SCHEDULES

  /*if (smart_mode && q->cached_tags_ntypes &&
      q->cached_tags_ntypes >= tags_ntypes_avg &&
      q->tags_coverage >= (max_tags_coverage / 2)) {

    perf_score *= 2;

  }*/
  
  /*if (smart_mode && q->tags_coverage) {
  
    if (max_tags_coverage - q->tags_coverage <= 0.01)
      perf_score *= 2;

  }*/
  
  if (smart_mode && !q->use_derived_tags && q->cached_tags_ntypes &&
      q->cached_tags_ntypes > tags_ntypes_avg &&
      max_tags_coverage - q->tags_coverage <= 0.02) {

    perf_score *= 2;

  }
  
  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;
  
  /*if (smart_mode && q->tags_fname && global_max_counter == q->cached_max_counter) {
    perf_score *= 2;
  }*/
  
  /*if (smart_mode && !q->use_derived_tags && q->cached_tags_ntypes &&
      q->cached_tags_ntypes > tags_ntypes_avg &&
      max_tags_coverage - q->tags_coverage <= 0.02) {

    perf_score *= 2;

  }*/

  return perf_score;

}

