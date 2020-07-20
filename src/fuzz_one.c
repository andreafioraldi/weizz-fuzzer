/*
   weizz - fuzz_one mega-routine
   -----------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "weizz.h"

#define SMART_STACKING_CONDITION (UR(chances+1) == 0)
//#define SMART_STACKING_CONDITION (UR(15) < 2)

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) {

    sh++;
    xor_val >>= 1;

  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) return 1;

  return 0;

}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++) {

    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {

      diffs++;
      ov = a;
      nv = b;

    }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {

    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);

    if (a != b) {

      diffs++;
      ov = a;
      nv = b;

    }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;

  }

  return 0;

}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++) {

    for (j = 0; j < sizeof(interesting_8); j++) {

      u32 tval =
          (old_val & ~(0xff << (i * 8))) | (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++) {

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j]) return 1;

  }

  return 0;

}

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

u8 fuzz_one() {

  s32 len, fd, temp_len, i, j;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued, orig_hit_cnt, new_hit_cnt = 0;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8 ret_val = 1, doing_det = 0;

  struct tags_info *tags      = NULL;
  struct tags_info *tags_orig = NULL;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;
  
  u64 fuzz_one_start_time = get_cur_time();
  
#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB)
      return 1;

  } else if (!queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

  /* When we have some weizz favoreds skip until one of them */
  // if (weizz_pending_favored && queue_cur->was_fuzzed) {

  // if (queue_cur->weizz_favored == 0)
  //  return 1;
  //}

#endif /* ^IGNORE_FINDS */

  if (not_on_tty) {

    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);

  }

  update_synced(queue_cur);

  /* Map the test case into memory. */

  fd = locked_open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_alloc_nozero(len);

  subseq_tmouts = 0;

  cur_depth = queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {

      queue_cur->exec_cksum = 0;

      res = calibrate_case(queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR) FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {

      cur_skipped_paths++;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (!queue_cur->trim_done && !queue_cur->tags_fname && !avoid_trim && !initial_testcases_num) {

    u8 res = trim_case(queue_cur, in_buf);

    if (res == FAULT_ERROR) FATAL("Unable to execute target application");

    if (stop_soon) {

      cur_skipped_paths++;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;

  }
  
  if (initial_testcases_num) --initial_testcases_num;

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);

  /* Children of a getdeps pass must pass before under smart havoc using the
     tags of the parent */

  /*********************
   * WEIZZ FIRST STAGE *
   *********************/
   
  if (full_weizz_mode || !avoid_getdeps && !queue_cur->did_only_getdeps &&
      !(getdeps_size_limit && len > getdeps_size_limit) &&
      (((queue_cur->tags_fname == NULL || queue_cur->use_derived_tags) &&
      (UR(100) < (fuzz_one_start_time - last_path_time) / 500)))) {
    
    if (queue_cur->use_derived_tags && !queue_cur->trim_done && !avoid_trim) {

      unlink(queue_cur->tags_fname);
      ck_free(queue_cur->tags_fname);
      queue_cur->tags_fname = NULL;
      queue_cur->use_derived_tags = 0;

      u8 res = trim_case(queue_cur, in_buf);

      if (res == FAULT_ERROR) FATAL("Unable to execute target application");

      if (stop_soon) {

        cur_skipped_paths++;

        goto abandon_entry;

      }

      /* Don't retry trimming, even if it failed. */

      queue_cur->trim_done = 1;

      if (len != queue_cur->len) {

        len       = queue_cur->len;
        orig_perf = perf_score = calculate_score(queue_cur);

      }

    }
    
    if (must_getdeps_asap) --must_getdeps_asap;
    
    if (weizz_first_stage(perf_score, in_buf, len))
      goto abandon_entry;
    
    if (discard_after_getdeps) {

      queue_cur->did_only_getdeps = 1;
      goto abandon_entry;

    }
  
  }

  queue_cur->did_only_getdeps = 0;

  memcpy(out_buf, in_buf, len);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;

  if (queue_cur->passed_getdeps) goto two_walking;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).

       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if ((stage_cur & 7) == 7) {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len      = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

two_walking:

  /* Two walking bits. */

  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  /* Four walking bits. */

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {

    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;

  }

  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~queue_cur->exec_cksum;

      if (cksum != queue_cur->exec_cksum) {

        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;

      }

    }

    out_buf[stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    blocks_eff_select += EFF_ALEN(len);

  } else {

    blocks_eff_select += eff_cnt;

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur   = 0;
  stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      stage_max--;
      continue;

    }

    stage_cur_byte = i;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

    if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur   = 0;
  stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      stage_max--;
      continue;

    }

    stage_cur_byte = i;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  if (no_arith) goto skip_arith;

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      stage_max -= 2 * ARITH_MAX;
      continue;

    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        stage_cur_val = j;
        out_buf[i]    = orig + j;

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        stage_cur_val = -j;
        out_buf[i]    = orig - j;

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      stage_max -= 4 * ARITH_MAX;
      continue;

    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        stage_cur_val         = j;
        *(u16 *)(out_buf + i) = orig + j;

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        stage_cur_val         = -j;
        *(u16 *)(out_buf + i) = orig - j;

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val         = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val         = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      *(u16 *)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      stage_max -= 4 * ARITH_MAX;
      continue;

    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        stage_cur_val         = j;
        *(u32 *)(out_buf + i) = orig + j;

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        stage_cur_val         = -j;
        *(u32 *)(out_buf + i) = orig - j;

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        stage_cur_val         = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        stage_cur_val         = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      *(u32 *)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name  = "interest 8/8";
  stage_short = "int8";
  stage_cur   = 0;
  stage_max   = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      stage_max -= sizeof(interesting_8);
      continue;

    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {

        stage_max--;
        continue;

      }

      stage_cur_val = interesting_8[j];
      out_buf[i]    = interesting_8[j];

      if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      stage_max -= sizeof(interesting_16);
      continue;

    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u16 *)(out_buf + i) = interesting_16[j];

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

    }

    *(u16 *)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      stage_max -= sizeof(interesting_32) >> 1;
      continue;

    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u32 *)(out_buf + i) = interesting_32[j];

        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else

        stage_max--;

    }

    *(u32 *)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name  = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;

  /* Insertion of user-supplied extras. */

  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++) {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++) {

      if (len + extras[j].len > MAX_FILE) {

        stage_max--;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

      if (common_light_fuzz_stuff(ex_tmp, len + extras[j].len)) {

        ck_free(ex_tmp);
        goto abandon_entry;

      }

      stage_cur++;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:

  if (!a_extras_cnt) goto skip_extras;

  stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, a_extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_light_fuzz_stuff(out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  if (smart_mode && queue_cur->tags_fname) {

    tags      = ck_alloc_nozero(sizeof(struct tags_info) + sizeof(struct tag) * len);
    tags_orig = ck_alloc_nozero(sizeof(struct tags_info) + sizeof(struct tag) * len);

    int tags_fd = locked_open(queue_cur->tags_fname, O_RDONLY);
    if (tags_fd < 0) PFATAL("Unable to open '%s'", queue_cur->tags_fname);

    struct stat t_stat;
    fstat(tags_fd, &t_stat);
    
    /* Fix a strnge error, TODO investigate */
    if (t_stat.st_size != sizeof(struct tags_info) + sizeof(struct tag) * queue_cur->len) {
    
      ck_free(tags);
      ck_free(tags_orig);
      tags = tags_orig = NULL;
      //ck_free(queue_cur->tags_fname);
      queue_cur->tags_fname = NULL;
      queue_cur->passed_getdeps = 0;
      queue_cur->cached_tags_ntypes = 0;
      queue_cur->tags_coverage = 0;
      queue_cur->use_derived_tags    = 0;
      
    } else {

      ck_read(tags_fd, tags, sizeof(struct tags_info) + sizeof(struct tag) * len,
              queue_cur->tags_fname);

      memcpy(tags_orig, tags, sizeof(struct tags_info) + len * sizeof(struct tag));

    }

    close(tags_fd);

  }

havoc_stage_noinit:

  stage_cur_byte = -1;

  u32 tags_havoc_finds    = 0;
  u32 tags_havoc_executed = 0;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) * perf_score /
                havoc_div / 100;

  } else {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  if (tags) stage_max *= 1.5;  // more air for smart fuzzing

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking              = 1 << (1 + UR(HAVOC_STACK_POW2));
    u8  changed_size              = 0;
    u32 higher_order_changed_size = 0;

    u8 has_done_tags_mut = 0;

    stage_cur_val = use_stacking;

    if (!stacking_mutation_mode && tags) {

      for (i = 0; i < use_stacking; i++) {

        u8 changed_structure =
            higher_order_fuzzing(&tags, &temp_len, &out_buf, len);
        if (changed_structure) higher_order_changed_size++;
        has_done_tags_mut = 1;

      }

      goto fuzz_one_common_fuzz_call;

    }

    u8 must_smart_interleave = (smart_mode && stacking_mutation_mode && tags) != 0;
    
    int num_tags_mut = 0;

    for (i = 0; i < use_stacking; i++) {

      u32 chances = 15 + ((extras_cnt + a_extras_cnt) ? 2 : 0);

      if (must_smart_interleave && !changed_size && /*num_tags_mut < 2 &&*/ SMART_STACKING_CONDITION) {

        u8 changed_structure =
            higher_order_fuzzing(&tags, &temp_len, &out_buf, len);
        if (changed_structure) higher_order_changed_size++;
        has_done_tags_mut = 1;
        ++num_tags_mut;
        continue;

      }

      switch (UR(chances)) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, UR(temp_len << 3));
          break;

        case 1:

          /* Set byte to interesting value. */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            *(u16 *)(out_buf + UR(temp_len - 1)) =
                interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16 *)(out_buf + UR(temp_len - 1)) =
                SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            *(u32 *)(out_buf + UR(temp_len - 3)) =
                interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32 *)(out_buf + UR(temp_len - 3)) =
                SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(out_buf + pos) =
                SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16 *)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(out_buf + pos) =
                SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(out_buf + pos) =
                SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32 *)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(out_buf + pos) =
                SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;

        case 11: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          u32 copy_from, copy_to, copy_len;

          if (temp_len < 2) break;

          copy_len = choose_block_len(temp_len - 1);

          copy_from = UR(temp_len - copy_len + 1);
          copy_to   = UR(temp_len - copy_len + 1);

          if (UR(4)) {

            if (copy_from != copy_to)
              memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          } else

            memset(out_buf + copy_to, UR(2) ? UR(256) : out_buf[UR(temp_len)],
                   copy_len);

          break;

        }

        case 12 ... 13: {

          //if (must_smart_interleave) { --i; break; }

          /*if (must_smart_interleave) {
            switch(UR(3 + ((extras_cnt + a_extras_cnt) != 0))) {
              case 0: goto clone_or_insert_mut;
              case 1: case 2: break;
              case 3: goto insert_extra_mut;
            }
          }*/

          /* Delete bytes. We're making this a bit more likely
             than insertion (the next option) in hopes of keeping
             files reasonably small. */

          u32 del_from, del_len;

          if (temp_len < 2) break;

          /* Don't delete too much. */

          del_len = choose_block_len(temp_len - 1);

          del_from = UR(temp_len - del_len + 1);

          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;
          changed_size = 1;

          break;

        }

        case 14:
        
          //if (must_smart_interleave) { --i; break; }

clone_or_insert_mut:;

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8 *new_buf;

            if (actually_clone) {

              clone_len  = choose_block_len(temp_len);
              clone_from = UR(temp_len - clone_len + 1);

            } else {

              clone_len  = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;

            }

            clone_to = UR(temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;
            changed_size = 1;

          }

          break;

          /* Values 15 and 16 can be selected only if there are any extras
             present in the dictionaries. */

        case 15: {

          /* Overwrite bytes with an extra. */

          if (!extras_cnt || (a_extras_cnt && UR(2))) {

            if (!a_extras_cnt) break;
            /* No user-specified extras or odds in our favor. Let's use an
               auto-detected one. */

            u32 use_extra = UR(a_extras_cnt);
            u32 extra_len = a_extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = UR(temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {

            if (!extras_cnt) break;
            /* No auto extras or odds in our favor. Use the dictionary. */

            u32 use_extra = UR(extras_cnt);
            u32 extra_len = extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = UR(temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

          }

          break;

        }

        case 16: {
          
          //if (must_smart_interleave) { --i; break; }

insert_extra_mut:;

          u32 use_extra, extra_len, insert_at;
          u8 *new_buf;

          insert_at = UR(temp_len + 1);

          /* Insert an extra. Do the same dice-rolling stuff as for the
             previous case. */

          if (!extras_cnt || (a_extras_cnt && UR(2))) {

            use_extra = UR(a_extras_cnt);
            extra_len = a_extras[use_extra].len;

            if (temp_len + extra_len >= MAX_FILE) break;

            new_buf = ck_alloc_nozero(temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {

            use_extra = UR(extras_cnt);
            extra_len = extras[use_extra].len;

            if (temp_len + extra_len >= MAX_FILE) break;

            new_buf = ck_alloc_nozero(temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

          }

          /* Tail */
          memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                 temp_len - insert_at);

          ck_free(out_buf);
          out_buf = new_buf;
          temp_len += extra_len;
          changed_size = 1;
          break;

        }

      }

    }

  fuzz_one_common_fuzz_call:

    if (has_done_tags_mut) {

      if (!splice_cycle) {

        stage_name  = "tags havoc";
        stage_short = "tags";

      } else {

        static u8 tmp[32];

        sprintf(tmp, "tags splice %u", splice_cycle);
        stage_name  = tmp;
        stage_short = "tags splice";

      }

    } else {

      if (!splice_cycle) {

        stage_name  = "havoc";
        stage_short = "havoc";

      } else {

        static u8 tmp[32];

        sprintf(tmp, "splice %u", splice_cycle);
        stage_name  = tmp;
        stage_short = "splice";

      }

    }

    u32 old_cnt = queued_paths;

    if (common_light_fuzz_stuff(out_buf, temp_len)) goto abandon_entry;

    if (old_cnt != queued_paths) {

      if (tags && !changed_size) {

        queue_top->tags_fname = alloc_printf(
            "%s/tags/%s", out_dir, strrchr(queue_top->fname, '/') + 1);

        s32 tags_fd =
            locked_open_mode(queue_top->tags_fname, O_WRONLY | O_CREAT, 0600);
        ck_write(tags_fd, tags, sizeof(struct tags_info) + sizeof(struct tag) * queue_top->len,
                 queue_top->tags_fname);
        close(tags_fd);

        add_to_tg_queue(queue_top);

        queue_top->use_derived_tags    = 1;
        queue_top->cached_tags_ntypes = tags->ntypes;
        queue_top->cached_max_counter = 0;
        u32 zcnt                      = 0;
        for (j = 0; j < temp_len; ++j) {

          if (tags->tags[j].cmp_id == 0) ++zcnt;
          else queue_top->cached_max_counter = MAX(queue_top->cached_max_counter, tags->tags[j].counter);

        }

        queue_top->tags_coverage = (double)(temp_len - zcnt) / temp_len;
        queue_top->parent        = queue_cur;

      write_tag_file_err:;

      }

    }

    if (has_done_tags_mut) {

      if (higher_order_changed_size > 0) {
        
        /* We restore the tags to the original state */
        tags = ck_realloc(tags, sizeof(struct tags_info) + len * sizeof(struct tag));
        memcpy(tags, tags_orig, sizeof(struct tags_info) + len * sizeof(struct tag));
      
      }

      if (old_cnt != queued_paths) tags_havoc_finds++;

      tags_havoc_executed++;

    }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);

    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {

        stage_max *= 2;
        perf_score *= 2;

      }

      havoc_queued = queued_paths;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (tags) {

    ck_free(tags);
    ck_free(tags_orig);
    tags = tags_orig = NULL;

  }

  if (!splice_cycle) {

    stage_finds[STAGE_TAGS_HAVOC] += tags_havoc_finds;
    stage_cycles[STAGE_TAGS_HAVOC] += tags_havoc_executed;

    stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt - tags_havoc_finds;
    stage_cycles[STAGE_HAVOC] += stage_max - tags_havoc_executed;

  } else {

    stage_finds[STAGE_TAGS_SPLICE] += tags_havoc_finds;
    stage_cycles[STAGE_TAGS_SPLICE] += tags_havoc_executed;

    stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt - tags_havoc_finds;
    stage_cycles[STAGE_SPLICE] += stage_max - tags_havoc_executed;

  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry *target;
    u32                 tid, split_at;
    u8 *                new_buf;
    s32                 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {

      ck_free(in_buf);
      in_buf = orig_in;
      len    = queue_cur->len;

    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do {

      tid = UR(queued_paths);

    } while (tid == current_entry);

    splicing_with = tid;
    target        = queue;

    while (tid >= 100) {

      target = target->next_100;
      tid -= 100;

    }

    while (tid--)
      target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {

      target = target->next;
      splicing_with++;

    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = locked_open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {

      ck_free(new_buf);
      goto retry_splicing;

    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    if (smart_mode && queue_cur->tags_fname && target->tags_fname) {

      tags      = ck_alloc_nozero(sizeof(struct tags_info) + sizeof(struct tag) * len);
      tags_orig = ck_alloc_nozero(sizeof(struct tags_info) + sizeof(struct tag) * len);

      int tags_fd = locked_open(target->tags_fname, O_RDONLY);
      if (tags_fd < 0) PFATAL("Unable to open '%s'", target->tags_fname);

      struct stat t_stat;
      fstat(tags_fd, &t_stat);
      
      if (t_stat.st_size != sizeof(struct tags_info) + sizeof(struct tag) * target->len) {
      
        ck_free(tags);
        ck_free(tags_orig);
        tags = tags_orig = NULL;
        //ck_free(target->tags_fname);
        target->tags_fname = NULL;
        target->passed_getdeps = 0;
        target->cached_tags_ntypes = 0;
        target->tags_coverage = 0;
        target->use_derived_tags    = 0;
        
      } else {

        ck_read(tags_fd, tags, sizeof(struct tags_info) + sizeof(struct tag) * len,
                target->tags_fname);

        close(tags_fd);

        tags_fd = locked_open(queue_cur->tags_fname, O_RDONLY);
        if (tags_fd < 0) PFATAL("Unable to open '%s'", queue_cur->tags_fname);

        u32 ntypes = tags->ntypes;

        ck_read(tags_fd, tags, sizeof(struct tags_info) + sizeof(struct tag) * split_at,
                queue_cur->tags_fname);

        tags->ntypes += ntypes;

        memcpy(tags_orig, tags, sizeof(struct tags_info) + len * sizeof(struct tag));
      
      }
      
      close(tags_fd);

    }

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage_noinit;

  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!queue_cur->did_only_getdeps && !stop_soon && !queue_cur->cal_failed &&
      !queue_cur->was_fuzzed) {

    queue_cur->was_fuzzed = 1;

    pending_not_fuzzed--;
    if (queue_cur->favored) pending_favored--;

  }
  
  if (queue_cur->tags_fname) {
  
    int tags_fd = locked_open(queue_cur->tags_fname, O_RDONLY);
    if (tags_fd < 0) PFATAL("Unable to open '%s'", queue_cur->tags_fname);

    struct stat t_stat;
    fstat(tags_fd, &t_stat);
    
    if (t_stat.st_size != sizeof(struct tags_info) + sizeof(struct tag) * queue_cur->len) {
    
      //ck_free(queue_cur->tags_fname);
      queue_cur->tags_fname = NULL;
      queue_cur->passed_getdeps = 0;
      queue_cur->cached_tags_ntypes = 0;
      queue_cur->tags_coverage = 0;
      queue_cur->use_derived_tags    = 0;
      
    }

    close(tags_fd);
    
  }

  munmap(orig_in, queue_cur->len);

  if (in_buf != orig_in) ck_free(in_buf);
  ck_free(out_buf);
  ck_free(eff_map);

  return ret_val;

}

