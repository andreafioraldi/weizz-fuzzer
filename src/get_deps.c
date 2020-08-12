/*
   weizz - get deps on a queue entry
   ---------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "weizz.h"

#define IS_V0 1
#define IS_V1 2

#define CK_DEPS_OVERLAP_BOUND 1

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf  = (_b);                        \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

u8 skip_surgical = 0;

void read_pass_stats(u8 *fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, pass_stats, CMP_MAP_W * sizeof(struct pass_info), fname);

  close(fd);

}

void write_pass_stats() {

  u8 *fname;
  s32 fd;

  fname = alloc_printf("%s/pass_stats", out_dir);
  fd    = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, pass_stats, CMP_MAP_W * sizeof(struct pass_info), fname);

  close(fd);
  ck_free(fname);

}

u8 weizz_perform_fuzz(u8 *buf, u32 len, u8* status) {

  u64 prev_queued, orig_hit_cnt, new_hit_cnt;

  prev_queued  = queued_paths;
  orig_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(common_light_fuzz_stuff(buf, len))) return 1;

  new_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt)) {

    *status = 1;

    if (queued_paths != prev_queued) {

      // if (surgical_use_derived_tags) {

        queue_top->use_derived_tags = 1;
        queue_top->tags_fname      = queue_cur->tags_fname;

        add_to_tg_queue(queue_top);

      // }

    }

  } else
    *status = 2;

  return 0;

}

///// Colorization

struct range {

  u32           start;
  u32           end;
  struct range *next;

};

static struct range *add_range(struct range *ranges, u32 start, u32 end) {

  struct range *r = ck_alloc_nozero(sizeof(struct range));
  r->start = start;
  r->end = end;
  r->next = ranges;
  return r;

}

static struct range *pop_biggest_range(struct range **ranges) {

  struct range *r = *ranges;
  struct range *prev = NULL;
  struct range *rmax = NULL;
  struct range *prev_rmax = NULL;
  u32           max_size = 0;

  while (r) {

    u32 s = r->end - r->start;
    if (s >= max_size) {

      max_size = s;
      prev_rmax = prev;
      rmax = r;

    }

    prev = r;
    r = r->next;

  }

  if (rmax) {

    if (prev_rmax) {

      prev_rmax->next = rmax->next;

    } else {

      *ranges = rmax->next;

    }

  }

  return rmax;

}

u8 weizz_get_exec_checksum(u8* buf, u32 len, u32* cksum) {

  u8 status;
  if (unlikely(weizz_perform_fuzz(buf, len, &status))) return 1;

  *cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  return 0;

}

static void rand_replace(u8* buf, u32 len) {

  u32 i;
  for (i = 0; i < len; ++i)
    buf[i] = UR(256);

}

u8 weizz_colorization(u8* buf, u32 len, u32 exec_cksum) {

  struct range* ranges = add_range(NULL, 0, len);
  u8*           backup = ck_alloc_nozero(len);

  u8 needs_write = 0;

  u64 orig_hit_cnt, new_hit_cnt;
  orig_hit_cnt = queued_paths + unique_crashes;

  stage_name = "getdeps";
  stage_short = "getdeps";
  stage_max = 1000;

  struct range* rng;
  stage_cur = stage_max;
  while ((rng = pop_biggest_range(&ranges)) != NULL && stage_cur) {

    u32 s = rng->end - rng->start;
    if (s == 0) goto empty_range;

    memcpy(backup, buf + rng->start, s);
    rand_replace(buf + rng->start, s);

    u32 cksum;
    u64 start_us = get_cur_time_us();
    if (unlikely(weizz_get_exec_checksum(buf, len, &cksum)))
      goto checksum_fail;
    u64 stop_us = get_cur_time_us();

    if (cksum != exec_cksum || (stop_us - start_us > 2 * queue_cur->exec_us)) {

      ranges = add_range(ranges, rng->start, rng->start + s / 2);
      ranges = add_range(ranges, rng->start + s / 2 + 1, rng->end);
      memcpy(buf + rng->start, backup, s);

    } else

      needs_write = 1;

  empty_range:
    ck_free(rng);
    --stage_cur;

  }
  
  if (stage_cur)
    queue_cur->fully_colorized = 1;

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_COLORIZATION] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_COLORIZATION] += stage_max - stage_cur;
  ck_free(backup);

  while (ranges) {

    rng = ranges;
    ranges = ranges->next;
    ck_free(rng);

  }

  // save the input with the high entropy

  if (needs_write) {

    s32 fd;

    unlink(queue_cur->fname);                            /* ignore errors */
    fd = locked_open_mode(queue_cur->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", queue_cur->fname);

    ck_write(fd, buf, len, queue_cur->fname);
    queue_cur->len = len;  // no-op, just to be 100% safe

    close(fd);

  }

  return 0;

checksum_fail:
  ck_free(backup);

  while (ranges) {

    rng = ranges;
    ranges = ranges->next;
    ck_free(rng);

  }

  return 1;

}

///// GetDeps

static int compare_header_counter(const void *p1, const void *p2, void *arg) {

  struct cmp_map* m = arg;
  return m->headers[*(u16*)p1].cnt - m->headers[*(u16*)p2].cnt;

}

u8 get_deps(u8 *buf, u32 len) {

  u8  r = 1;
  s32 b, i, j;

  u64 orig_hit_cnt, new_hit_cnt = 0;
  u32 nbits = len << 3;
  
  u8 flip_byte_level = 0;
  
  if (!force_bits_getdeps && (total_cal_us / total_cal_cycles) * nbits >= 1000000*60) {
    // heuristically flip byte level if the stage time is estimated more than 1 minute
    flip_byte_level = 1;
  }

  if (flip_byte_level) {

    stage_name = "getdeps (bytes)";
    stage_max  = len * 2 - 2;

  } else {

    stage_name = "getdeps (bits)";
    stage_max  = nbits;

  }

  stage_short = "getdeps";
  stage_cur   = 0;

  stage_val_type = STAGE_VAL_NONE;

  /* First run to collect original cmp data */

  if (common_heavy_fuzz_stuff(buf, len)) {

    memset(cmp_map->headers, 0, sizeof(cmp_map->headers));
    return 1;

  }

  u32 hash_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  u32 prev_cksum = hash_cksum;

  memcpy(&orig_cmp_map, cmp_map, sizeof(struct cmp_map));
  
  memset(cmp_map->headers, 0, sizeof(cmp_map->headers));

  orig_hit_cnt = queued_paths + unique_crashes;

  /* Flip based analysis */

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

  for (b = 0; b < nbits; ++b) {

    u32 byte_index = b >> 3;
    stage_cur_byte = byte_index;

    if (flip_byte_level) {

      if ((b & 7) != 0 && (b & 7) != 7) continue;

      stage_cur = (byte_index << 1) + ((b & 7) != 0);

    } else {

      stage_cur = b;

    }

    u64 prev_queued = queued_paths;

    FLIP_BIT(buf, b);
    if (common_heavy_fuzz_stuff(buf, len)) goto exit_get_deps;
    FLIP_BIT(buf, b);

    if (prev_queued != queued_paths) {

      //if (surgical_use_derived_tags) {

        queue_top->use_derived_tags = 1;
        queue_top->tags_fname      = queue_cur->tags_fname;

        add_to_tg_queue(queue_top);

      //}

    }

    if ((b & 7) == 7) {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (b == nbits - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = buf[b >> 3];
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

      if (cksum != hash_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = buf[b >> 3];
        a_len++;

      }

    }

    for (i = 0; i < CMP_MAP_W; ++i) {

      struct cmp_header* h = &cmp_map->headers[i];

      if (likely(h->hits == 0)) continue;
      
      struct cmp_operands* ops = cmp_map->log[i];

      if (!orig_cmp_map.headers[i].hits) goto skip_byte_deps;
      
      // if (pass_stats[h->cmp_id].total)
      //  goto skip_byte_deps;

      u32 hits = h->hits;

      struct cmp_header* o_h = &orig_cmp_map.headers[i];
      u32 o_hits = o_h->hits;
      
      tags_counters[h->id] = MIN(tags_counters[h->id], h->cnt); // take the min

      if (hits == o_hits) {
      
        size_t hits_masked = hits & (CMP_MAP_H - 1);
        struct cmp_operands* o_ops = orig_cmp_map.log[i];

        for (j = 0; j < hits_masked; ++j) {
        
          if (ops[j].v0 != o_ops[j].v0)
            V0_DEPS_SET(i, j, byte_index);
          if (ops[j].v1 != o_ops[j].v1)
            V1_DEPS_SET(i, j, byte_index);

        }

      } else {

        // cnt > orig_cnt
        s64 span = abs(hits - o_hits);
        if (span > CMP_MAP_H) // not comparable data
          continue;

        struct cmp_operands* o_ops = orig_cmp_map.log[i];
        size_t hits_masked = hits & (CMP_MAP_H - 1);
        size_t first_idx = o_hits & (CMP_MAP_H - 1);
        size_t start, end;

        if (hits_masked < first_idx) {

          start = hits_masked;
          end = first_idx;

        } else {

          start = first_idx;
          end = hits_masked;

        }

        for (j = start; j < end; ++j) {
        
          if (ops[j].v0 != o_ops[j].v0)
            IMPL_V0_DEPS_SET(i, j, byte_index);
          if (ops[j].v1 != o_ops[j].v1)
            IMPL_V1_DEPS_SET(i, j, byte_index);

        }

      }

    skip_byte_deps:
      // clear
      cmp_map->headers[i].hits = 0;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_GETDEPS] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_GETDEPS] += stage_max;

  r = 0;

exit_get_deps:

  if (r) {

    /* Cleanup deps[i][j] cause we skipped surgical fuzz loop */

    for (i = 0; i < CMP_MAP_W; ++i) {
    
      if (likely(!weizz_deps[i])) continue;

      struct cmp_header* o_h = &orig_cmp_map.headers[i];

      size_t hits_masked = o_h->hits & (CMP_MAP_H - 1);

      for (j = 0; j < hits_masked; ++j) {

        if (DEPS_EXISTS(i, j)) {

          ck_free(DEPS_GET(i, j));
          DEPS_GET(i, j) = NULL;

        }

      }

      ck_free(weizz_deps[i]);
      weizz_deps[i] = 0;

    }

    memset(cmp_map->headers, 0, sizeof(cmp_map->headers));

  }

  return r;

}

///// Place Tags

u8 place_tags(u32 cmp_id, u32 len, u8* deps_bitvec, struct tags_info* ti, u8 is_i2s, u8 is_checksum, u16* checksum_coverage) {

  u32 dep_bytes_num = 0, v0_dep_bytes_num = 0, v1_dep_bytes_num = 0;
  u32 v0_near_bytes_num = 0, v1_near_bytes_num = 0;

  u8 has_placed_tag = 0;
  s32 i, j;
  
  s32 f_v1_i = -1, f_v0_i = -1;
  
  for (i = 0; i < len; ++i) {

    if (V0_HASDEP(deps_bitvec, i)) {

      if (f_v0_i < 0) f_v1_i = i;
      ++v0_dep_bytes_num;
      ++dep_bytes_num;

      if (V1_HASDEP(deps_bitvec, i)) {
      
        if (f_v1_i < 0) f_v1_i = i;
        ++v1_dep_bytes_num;

      } else {
      
        if (f_v1_i >= 0)
          v1_near_bytes_num = MAX(i-f_v1_i, v1_near_bytes_num);
        f_v1_i = -1;
      
      }

    } else if (V1_HASDEP(deps_bitvec, i)) {
    
      if (f_v0_i >= 0)
        v0_near_bytes_num = MAX(i-f_v0_i, v0_near_bytes_num);
      f_v0_i = -1;
  
      if (f_v1_i < 0) f_v1_i = i;
      ++v1_dep_bytes_num;
      ++dep_bytes_num;

    } else {

      if (f_v1_i >= 0)
        v1_near_bytes_num = MAX(i-f_v1_i, v1_near_bytes_num);
      f_v1_i = -1;
    
    }

  }
  
  if (v0_dep_bytes_num <= 1 && v1_dep_bytes_num <= 1) return 0;

  for (i = 0; i < len; ++i) {
  
    u32 prev_near_num = 0;
    if (ti->tags[i].cmp_id) {
    
      for (j = i; j < len && ti->tags[i].cmp_id == ti->tags[j].cmp_id; ++j);
      prev_near_num = j - i;
    
    }

    if (V0_HASDEP(deps_bitvec, i)) {

      if (V1_HASDEP(deps_bitvec, i)) {

        if (!ti->tags[i].cmp_id || (is_checksum & IS_V1) || (v1_near_bytes_num < prev_near_num && prev_near_num > 4 &&
             !(ti->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

          if ((i == 0 || ti->tags[i-1].cmp_id != cmp_id) && (i == len-1 || !V1_HASDEP(deps_bitvec, i+1)))
            continue;

          ti->tags[i].cmp_id  = cmp_id;
          ti->tags[i].parent  = last_cmp_that_placed_tag;
          ti->tags[i].counter = orig_cmp_map.headers[cmp_id].cnt;
          ti->tags[i].flags |=
              (is_i2s & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
          has_placed_tag         = 1;
          
          if (checksum_coverage[i])
            ti->tags[i].depends_on = checksum_coverage[i];

          if (is_checksum == IS_V1)
            ti->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

        }

      }
      
      if (!ti->tags[i].cmp_id || (is_checksum & IS_V0) || (v0_near_bytes_num < prev_near_num && prev_near_num > 4 &&
             !(ti->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || ti->tags[i-1].cmp_id != cmp_id) && (i == len-1 || !V0_HASDEP(deps_bitvec, i+1)))
          continue;

        ti->tags[i].cmp_id  = cmp_id;
        ti->tags[i].parent  = last_cmp_that_placed_tag;
        ti->tags[i].counter = orig_cmp_map.headers[cmp_id].cnt;
        ti->tags[i].flags |=
            (is_i2s & IS_V0) ? TAG_IS_INPUT_TO_STATE : 0;
        has_placed_tag         = 1;
        
        if (checksum_coverage[i])
          ti->tags[i].depends_on = checksum_coverage[i];

        if (is_checksum == IS_V0)
          ti->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

      }

    } else if (V1_HASDEP(deps_bitvec, i)) {

      if (!ti->tags[i].cmp_id || (is_checksum & IS_V1) || (v1_near_bytes_num < prev_near_num && prev_near_num > 4 &&
             !(ti->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || ti->tags[i-1].cmp_id != cmp_id) && (i == len-1 || !V1_HASDEP(deps_bitvec, i+1)))
          continue;

        ti->tags[i].cmp_id  = cmp_id;
        ti->tags[i].parent  = last_cmp_that_placed_tag;
        ti->tags[i].counter = orig_cmp_map.headers[cmp_id].cnt;
        ti->tags[i].flags |=
            (is_i2s & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
        has_placed_tag         = 1;
        
        if (checksum_coverage[i])
          ti->tags[i].depends_on = checksum_coverage[i];

        if (is_checksum == IS_V1)
          ti->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

      }

    }

  }
  /*
  //TODO optimize do in a single loop
  //IMPL has less priority
  
  dep_bytes_num = v0_dep_bytes_num = v1_dep_bytes_num = 0;

  for (i = 0; i < len; ++i) {

    if (IMPL_V0_HASDEP(deps_bitvec, i)) {

      ++v0_dep_bytes_num;

      if (IMPL_V1_HASDEP(deps_bitvec, i)) { ++v1_dep_bytes_num; }

    } else if (IMPL_V1_HASDEP(deps_bitvec, i)) {

      ++v1_dep_bytes_num;

    }

    ++dep_bytes_num;

  }

  v0_brothers    = MIN(v0_dep_bytes_num, 255);
  v1_brothers    = MIN(v1_dep_bytes_num, 255);

  for (i = 0; i < len; ++i) {

    if (IMPL_V0_HASDEP(deps_bitvec, i)) {

      if (IMPL_V1_HASDEP(deps_bitvec, i)) {

        // Prioritize checksum related cmp or use a rate
        if (is_checksum & IS_V1 || !ti->tags[i].cmp_id ||
            ((v1_brothers < ti->tags[i].brothers &&
             ti->tags[i].brothers > 4) &&
             !(ti->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

          if ((i == 0 || ti->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !IMPL_V1_HASDEP(deps_bitvec, i+1)))
          continue;

          ti->tags[i].cmp_id  = cmp_cur_head.id;
          ti->tags[i].parent  = last_cmp_that_placed_tag;
          ti->tags[i].counter = cmp_cur_head.cnt;
          ti->tags[i].flags   = ti->tags[i].flags & TAG_IS_LEN;
          ti->tags[i].flags |=
              (is_i2s & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
          ti->tags[i].brothers = v1_brothers;
          has_placed_tag         = 1;

          if (checksum_coverage[i]) {

            ti->tags[i].depends_on = checksum_coverage[i];

          }

          if (is_checksum == IS_V1) {

            ti->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

          }

        }

      }

      // Prioritize checksum related cmp or use a rate
      if (is_checksum & IS_V0 || !ti->tags[i].cmp_id ||
          (v0_brothers < ti->tags[i].brothers && ti->tags[i].brothers > 4 &&
           !(ti->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || ti->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !IMPL_V0_HASDEP(deps_bitvec, i+1)))
          continue;

        ti->tags[i].cmp_id  = cmp_cur_head.id;
        ti->tags[i].parent  = last_cmp_that_placed_tag;
        ti->tags[i].counter = cmp_cur_head.cnt;
        ti->tags[i].flags   = ti->tags[i].flags & TAG_IS_LEN;
        ti->tags[i].flags |= TAG_CMP_IS_LEFT;
        ti->tags[i].flags |=
            (is_i2s & IS_V0) ? TAG_IS_INPUT_TO_STATE : 0;
        ti->tags[i].brothers = v0_brothers;
        has_placed_tag         = 1;

        if (checksum_coverage[i]) {

          ti->tags[i].depends_on = checksum_coverage[i];

        }

        if (is_checksum == IS_V0) {

          ti->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

        }

      }

    } else if (IMPL_V1_HASDEP(deps_bitvec, i)) {

      // Prioritize checksum related cmp or use a rate
      if (is_checksum & IS_V1 || !ti->tags[i].cmp_id ||
          (v1_brothers < ti->tags[i].brothers && ti->tags[i].brothers > 4 &&
           !(ti->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || ti->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !IMPL_V1_HASDEP(deps_bitvec, i+1)))
          continue;

        ti->tags[i].cmp_id  = cmp_cur_head.id;
        ti->tags[i].parent  = last_cmp_that_placed_tag;
        ti->tags[i].counter = cmp_cur_head.cnt;
        ti->tags[i].flags   = ti->tags[i].flags & TAG_IS_LEN;
        ti->tags[i].flags |=
            (is_i2s & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
        ti->tags[i].brothers = v1_brothers;
        has_placed_tag         = 1;

        if (checksum_coverage[i]) {

          ti->tags[i].depends_on = checksum_coverage[i];

        }

        if (is_checksum == IS_V1) {

          ti->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

        }

      }

    }

  }
  */
  return has_placed_tag;

}

//// Locked Havoc

u8 locked_havoc(u32 perf_score, u32 key, u8 *deps_bitvec, u8* buf, u32 len, u8* status) {

  u8 r = 1;
  u32 i, j = 0;
  
  struct cmp_header* h = &orig_cmp_map.headers[key];

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_H) loggeds = CMP_MAP_H;
  
  u32 *mutables_idx_map;
  u32 not_deps = 0;
  
  u32 v0_count_deps = 0, v1_count_deps = 0;
  for (i = 0; i < len; ++i) {
    
    if (ANY_V0_HASDEP(deps_bitvec, i)) ++v0_count_deps;
    if (ANY_V1_HASDEP(deps_bitvec, i)) ++v1_count_deps;
  
  }

  if (v0_count_deps <= 9 && v1_count_deps <= 9) {

    mutables_idx_map = ck_alloc_nozero((v0_count_deps + v1_count_deps) * sizeof(u32));

    for (i = 0; i < len; ++i) {

      if (ANY_V0_HASDEP(deps_bitvec, i))
        mutables_idx_map[j++] = i;
      else if (ANY_V1_HASDEP(deps_bitvec, i))
        mutables_idx_map[j++] = i;
      else
        ++not_deps;

    }

  } else if (v0_count_deps > 9 && v1_count_deps <= 9 && v1_count_deps) {

    mutables_idx_map = ck_alloc_nozero((v0_count_deps + v1_count_deps) * sizeof(u32));

    for (i = 0; i < len; ++i) {

      if (ANY_V1_HASDEP(deps_bitvec, i))
        mutables_idx_map[j++] = i;
      else
        ++not_deps;

    }

  } else if (v0_count_deps <= 9 && v1_count_deps > 9 && v0_count_deps) {

    mutables_idx_map = ck_alloc_nozero((v0_count_deps + v1_count_deps) * sizeof(u32));

    for (i = 0; i < len; ++i) {

      if (ANY_V0_HASDEP(deps_bitvec, i))
        mutables_idx_map[j++] = i;
      else
        ++not_deps;

    }

  } else {

    return 0;

  }

  u32 count_deps = len - not_deps;

  stage_cur_byte = -1;

  static u8 tmp[32];
  sprintf(tmp, "locked %d/%d", sorted_cmps_idx, sorted_cmps_len);
  stage_name = tmp;
  stage_short = "locked";
  stage_max   = HAVOC_CYCLES * perf_score / havoc_div /
              (40 - count_deps);  // / 100 not needed, many will be skipped

  if (stage_max > count_deps * 256)
    stage_max = count_deps * 256;

  u8* saved_buf = buf;
  
  buf = ck_alloc_nozero(len);
  memcpy(buf, saved_buf, len);

  u64 orig_hit_cnt       = queued_paths + unique_crashes;
  u64 stage_orig_hit_cnt = orig_hit_cnt;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;

    for (i = 0; i < use_stacking; i++) {

      switch (UR(13 + ((extras_cnt + a_extras_cnt) ? 1 : 0))) {

        case 0: {

          /* Flip a single bit somewhere. Spooky! */

          s32 bit_idx = (mutables_idx_map[UR(count_deps)] << 3) + UR(8);

          FLIP_BIT(buf, bit_idx);

          break;

        }

        case 1: {

          /* Set byte to interesting value. */

          u8 val;

          switch (UR(3)) {

            case 0: val = orig_cmp_map.log[key][1 + UR(loggeds)].v0; break;
            case 1: val = orig_cmp_map.log[key][1 + UR(loggeds)].v1; break;
            default: val = interesting_8[UR(sizeof(interesting_8))]; break;

          }

          s32 byte_idx      = mutables_idx_map[UR(count_deps)];
          buf[byte_idx] = val;

          break;

        }

        case 2: {

          /* Set word to interesting value, randomly choosing endian. */

          if (len < 2) break;

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx >= len - 1) break;

          switch (UR(6)) {

            case 0:
              *(u16 *)(buf + byte_idx) = orig_cmp_map.log[key][1 + UR(loggeds)].v0;
              break;
            case 1:
              *(u16 *)(buf + byte_idx) = orig_cmp_map.log[key][1 + UR(loggeds)].v1;
              break;
            case 2:
              *(u16 *)(buf + byte_idx) =
                  SWAP16(orig_cmp_map.log[key][1 + UR(loggeds)].v0);
              break;
            case 3:
              *(u16 *)(buf + byte_idx) =
                  SWAP16(orig_cmp_map.log[key][1 + UR(loggeds)].v1);
              break;
            case 4:
              *(u16 *)(buf + byte_idx) =
                  interesting_16[UR(sizeof(interesting_16) >> 1)];
              break;
            case 5:
              *(u16 *)(buf + byte_idx) =
                  SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);
              break;

          }

          break;

        }

        case 3: {

          /* Set dword to interesting value, randomly choosing endian. */

          if (len < 4) break;

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx >= len - 3) break;

          switch (UR(6)) {

            case 0:
              *(u32 *)(buf + byte_idx) = orig_cmp_map.log[key][1 + UR(loggeds)].v0;
              break;
            case 1:
              *(u32 *)(buf + byte_idx) = orig_cmp_map.log[key][1 + UR(loggeds)].v1;
              break;
            case 2:
              *(u32 *)(buf + byte_idx) =
                  SWAP32(orig_cmp_map.log[key][1 + UR(loggeds)].v0);
              break;
            case 3:
              *(u32 *)(buf + byte_idx) =
                  SWAP32(orig_cmp_map.log[key][1 + UR(loggeds)].v1);
              break;
            case 4:
              *(u32 *)(buf + byte_idx) =
                  interesting_32[UR(sizeof(interesting_32) >> 2)];
              break;
            case 5:
              *(u32 *)(buf + byte_idx) =
                  SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);
              break;

          }

          break;

        }

        case 4: {

          /* Set qword to interesting value, randomly choosing endian. */

          if (len < 8) break;

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx >= len - 7) break;

          switch (UR(6)) {

            case 0:
              *(u64 *)(buf + byte_idx) = orig_cmp_map.log[key][1 + UR(loggeds)].v0;
              break;
            case 1:
              *(u64 *)(buf + byte_idx) = orig_cmp_map.log[key][1 + UR(loggeds)].v1;
              break;
            case 2:
              *(u64 *)(buf + byte_idx) =
                  SWAP32(orig_cmp_map.log[key][1 + UR(loggeds)].v0);
              break;
            case 3:
              *(u64 *)(buf + byte_idx) =
                  SWAP32(orig_cmp_map.log[key][1 + UR(loggeds)].v1);
              break;
            case 4:
              *(u64 *)(buf + byte_idx) =
                  (s64)interesting_32[UR(sizeof(interesting_32) >> 2)];
              break;
            case 5:
              *(u64 *)(buf + byte_idx) =
                  SWAP64((s64)interesting_32[UR(sizeof(interesting_32) >> 2)]);
              break;

          }

          break;

        }

        case 5: {

          /* Randomly subtract from byte. */

          s32 byte_idx = mutables_idx_map[UR(count_deps)];
          buf[byte_idx] -= 1 + UR(ARITH_MAX);

          break;

        }

        case 6: {

          /* Randomly add to byte. */

          s32 byte_idx = mutables_idx_map[UR(count_deps)];
          buf[byte_idx] += 1 + UR(ARITH_MAX);

          break;

        }

        case 7: {

          /* Randomly subtract from word, random endian. */

          if (len < 2) break;

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx >= len - 1) break;

          if (UR(2)) {

            *(u16 *)(buf + byte_idx) -= 1 + UR(ARITH_MAX);

          } else {

            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(buf + byte_idx) =
                SWAP16(SWAP16(*(u16 *)(buf + byte_idx)) - num);

          }

          break;

        }

        case 8: {

          /* Randomly add to word, random endian. */

          if (len < 2) break;

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx >= len - 1) break;

          if (UR(2)) {

            *(u16 *)(buf + byte_idx) += 1 + UR(ARITH_MAX);

          } else {

            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(buf + byte_idx) =
                SWAP16(SWAP16(*(u16 *)(buf + byte_idx)) + num);

          }

          break;

        }

        case 9: {

          /* Randomly subtract from dword, random endian. */

          if (len < 4) break;

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx >= len - 3) break;

          if (UR(2)) {

            *(u32 *)(buf + byte_idx) -= 1 + UR(ARITH_MAX);

          } else {

            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(buf + byte_idx) =
                SWAP32(SWAP32(*(u32 *)(buf + byte_idx)) - num);

          }

          break;

        }

        case 10: {

          /* Randomly add to dword, random endian. */

          if (len < 4) break;

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx >= len - 3) break;

          if (UR(2)) {

            *(u32 *)(buf + byte_idx) += 1 + UR(ARITH_MAX);

          } else {

            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(buf + byte_idx) =
                SWAP32(SWAP32(*(u32 *)(buf + byte_idx)) + num);

          }

          break;

        }

        case 11: {

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          s32 byte_idx = mutables_idx_map[UR(count_deps)];
          buf[byte_idx] ^= 1 + UR(255);

          break;

        }

        case 12: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          u32 copy_from, copy_to, copy_len;

          if (len < 2) break;

          copy_len = choose_block_len(len - 1);

          copy_from = UR(len - copy_len + 1);

          s32 byte_idx = mutables_idx_map[UR(count_deps)];

          if (byte_idx + copy_len >= len) break;

          copy_to = byte_idx;

          if (UR(4)) {

            if (copy_from != copy_to)
              memmove(buf + copy_to, buf + copy_from, copy_len);

          } else

            memset(buf + copy_to, UR(2) ? UR(256) : buf[UR(len)],
                   copy_len);

          break;

        }

          /* Value12  can be selected only if there are any extras
             present in the dictionaries. */

        case 13: {

          /* Overwrite bytes with an extra. */

          if (!extras_cnt || (a_extras_cnt && UR(2))) {

            /* No user-specified extras or odds in our favor. Let's use an
               auto-detected one. */

            u32 use_extra = UR(a_extras_cnt);
            u32 extra_len = a_extras[use_extra].len;
            u32 insert_at;

            if (extra_len > len) break;

            s32 byte_idx = mutables_idx_map[UR(count_deps)];

            if (byte_idx + extra_len >= len) break;

            insert_at = byte_idx;
            memcpy(buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {

            /* No auto extras or odds in our favor. Use the dictionary. */

            u32 use_extra = UR(extras_cnt);
            u32 extra_len = extras[use_extra].len;
            u32 insert_at;

            if (extra_len > len) break;

            s32 byte_idx = mutables_idx_map[UR(count_deps)];

            if (byte_idx + extra_len >= len) break;

            insert_at = byte_idx;
            memcpy(buf + insert_at, extras[use_extra].data, extra_len);

          }

          break;

        }

      }

    }

    if (unlikely(weizz_perform_fuzz(buf, len, status)))
      goto exit_locked_havoc;

    if (*status == 1) break;

    /* buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    memcpy(buf, saved_buf, len);

  }

  r = 0;

  u64 stage_new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_LOCKED_HAVOC] += stage_new_hit_cnt - stage_orig_hit_cnt;
  stage_cycles[STAGE_LOCKED_HAVOC] += stage_cur + 1;

exit_locked_havoc:

  ck_free(mutables_idx_map);
  ck_free(buf);

  return r;

}

void try_to_add_to_dict(u64 v, u8 shape) {

  u8* b = (u8*)&v;

  u32 k;
  u8  cons_ff = 0, cons_0 = 0;
  for (k = 0; k < shape; ++k) {

    if (b[k] == 0)
      ++cons_0;
    else if (b[k] == 0xff)
      ++cons_0;
    else
      cons_0 = cons_ff = 0;

    if (cons_0 > 1 || cons_ff > 1) return;

  }

  maybe_add_auto((u8*)&v, shape);

  u64 rev;
  switch (shape) {

    case 1: break;
    case 2:
      rev = SWAP16((u16)v);
      maybe_add_auto((u8*)&rev, shape);
      break;
    case 4:
      rev = SWAP32((u32)v);
      maybe_add_auto((u8*)&rev, shape);
      break;
    case 8:
      rev = SWAP64(v);
      maybe_add_auto((u8*)&rev, shape);
      break;

  }

}

u8 weizz_cmp_extend_encoding(struct cmp_header* h, u64 pattern, u64 repl, u32 idx, u8* buf, u32 len, u8 do_reverse, u8* status) {

  u64* buf_64 = (u64*)&buf[idx];
  u32* buf_32 = (u32*)&buf[idx];
  u16* buf_16 = (u16*)&buf[idx];
  u8*  buf_8  = &buf[idx];

  u32 its_len = len - idx;
  //*status = 0;

  if (SHAPE_BYTES(h->shape) >= 8) {

    if (its_len >= 8 && *buf_64 == pattern) {

      *buf_64 = repl;
      if (unlikely(weizz_perform_fuzz(buf, len, status))) return 1;
      *buf_64 = pattern;

    }

    // reverse encoding
    if (do_reverse && *status != 1)
      if (unlikely(weizz_cmp_extend_encoding(h, SWAP64(pattern), SWAP64(repl), idx,
                                       buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) >= 4 && *status != 1) {

    if (its_len >= 4 && *buf_32 == (u32)pattern) {

      *buf_32 = (u32)repl;
      if (unlikely(weizz_perform_fuzz(buf, len, status))) return 1;
      *buf_32 = pattern;

    }

    // reverse encoding
    if (do_reverse && *status != 1)
      if (unlikely(weizz_cmp_extend_encoding(h, SWAP32(pattern), SWAP32(repl), idx,
                                       buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) >= 2 && *status != 1) {

    if (its_len >= 2 && *buf_16 == (u16)pattern) {

      *buf_16 = (u16)repl;
      if (unlikely(weizz_perform_fuzz(buf, len, status))) return 1;
      *buf_16 = (u16)pattern;

    }

    // reverse encoding
    if (do_reverse && *status != 1)
      if (unlikely(weizz_cmp_extend_encoding(h, SWAP16(pattern), SWAP16(repl), idx,
                                       buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) >= 1 && *status != 1) {

    if (its_len >= 1 && *buf_8 == (u8)pattern) {

      *buf_8 = (u8)repl;
      if (unlikely(weizz_perform_fuzz(buf, len, status)))
        return 1;
      *buf_8 = (u8)pattern;

    }

  }

  return 0;

}

u8 weizz_rtn_extend_encoding(struct cmp_header *h, u8 *pattern, u8 *repl,
                                    u32 idx, u8 *buf, u32 len, u8 *status) {

  u32 i;
  u32 its_len = MIN(32, len - idx);

  u8 save[32];
  memcpy(save, &buf[idx], its_len);

  *status = 0;

  for (i = 0; i < its_len; ++i) {

    if (pattern[i] != buf[idx + i] || *status == 1) {

      break;

    }

    buf[idx + i] = repl[i];

    if (unlikely(weizz_perform_fuzz(buf, len, status))) { return 1; }

  }

  memcpy(&buf[idx], save, i);
  return 0;

}

u8 weizz_rtn_fuzz(u32 key, u8 *buf, u32 len) {

  if (skip_surgical ||
      (pass_stats[key].total && (UR(pass_stats[key].total) >=
       pass_stats[key].failed || pass_stats[key].total == 255)))
    return 0;

  u8 r = 1;
  static u8 tmp[32];

  struct cmp_header *h = &orig_cmp_map.headers[key];
  u32 i, j, idx;

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_RTN_H) { loggeds = CMP_MAP_RTN_H; }

  u8 status = 0;
  // opt not in the paper
  u32 fails = 0;
  u8  found_one = 0;
  
  sprintf(tmp, "rtn %d/%d", sorted_cmps_idx, sorted_cmps_len);
  stage_short = "rtn";
  stage_name = tmp;
  
  stage_max = loggeds;

  for (i = 0; i < loggeds; ++i) {
  
    stage_cur = i;

    fails = 0;

    struct cmpfn_operands *o =
        &((struct cmpfn_operands *)&orig_cmp_map.log[key])[i];

    // opt not in the paper
    for (j = 0; j < i; ++j) {

      if (!memcmp(&((struct cmpfn_operands *)&orig_cmp_map.log[key])[j], o,
                  sizeof(struct cmpfn_operands))) {
 
        goto rtn_fuzz_next_iter;

      }

    }

    for (idx = 0; idx < len && fails < 8; ++idx) {

      if (unlikely(weizz_rtn_extend_encoding(h, o->v0, o->v1, idx, buf, len, &status))) {

        goto exit_weizz_rtn_fuzz;

      }

      if (status == 2) {

        ++fails;

      } else if (status == 1) {

        break;

      }

      if (unlikely(weizz_rtn_extend_encoding(h, o->v1, o->v0, idx, buf, len, &status))) {

        goto exit_weizz_rtn_fuzz;

      }

      if (status == 2) {

        ++fails;

      } else if (status == 1) {

        break;

      }

    }
    
    if (status == 1) { found_one = 1; }

    // If failed, add to dictionary
    if (fails == 8) {

      if (pass_stats[key].total == 0) {

        maybe_add_auto(o->v0, SHAPE_BYTES(h->shape));
        maybe_add_auto(o->v1, SHAPE_BYTES(h->shape));

      }

    }

  rtn_fuzz_next_iter:;

  }

  if (!found_one && pass_stats[key].failed < 0xff)
    pass_stats[key].failed++;
  if (pass_stats[key].total < 0xff)
    pass_stats[key].total++;

  r = 0;

exit_weizz_rtn_fuzz:

  for (i = 0; i < loggeds; ++i) {
  
    if (DEPS_EXISTS(key, i)) {

      u8 *deps_bitvec = DEPS_GET(key, i);
      DEPS_GET(key, i) = NULL;
      ck_free(deps_bitvec);
    
    }

  }

  return r;

  return 0;

}


u8 weizz_cmp_fuzz(u32 perf_score, u32 key, u8 *buf, u32 len, struct tags_info *ti, u8* bruted_bits, u16* checksum_coverage, u8 is_i2s, u8 is_checksum) {

  u8 r = 1;
  u8 skip_cmp = 0;

  static u8 tmp[32];

  struct cmp_header* h = &orig_cmp_map.headers[key];
  u32                i, j, idx;

  if (h->type == CMP_TYPE_RTN)
    return weizz_rtn_fuzz(key, buf, len);
  
  if (skip_surgical) skip_cmp = 1;
  
  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_H) loggeds = CMP_MAP_H;

  if (pass_stats[key].total && (UR(pass_stats[key].total) >= pass_stats[key].failed || pass_stats[key].total == 255))
    skip_cmp = 1;

  u8 found = 0;

  sprintf(tmp, "cmp %d/%d", sorted_cmps_idx, sorted_cmps_len);
  stage_short = "cmp";
  stage_name = tmp;
  
  stage_max = loggeds;
  
  //fprintf(stderr, "cmp %d/%d   %d   %d\n", sorted_cmps_idx, sorted_cmps_len, loggeds, skip_cmp);

  // opt not in the paper
  for (i = 0; i < loggeds; ++i) {
  
    u32 fails = 0;
    u8 status = 0;
    
    stage_cur = i;
  
    if (DEPS_EXISTS(key, i)) {

      u8 *deps_bitvec = DEPS_GET(key, i);
      u32 v0_count_deps = 0, v1_count_deps = 0;

      struct cmp_operands* o = &orig_cmp_map.log[key][i];

      u8 skip_this = skip_cmp;
      if (found)
        skip_this = 1;
      else {
      
        for (j = 0; j < i; ++j)
          if (orig_cmp_map.log[key][j].v0 == o->v0 && orig_cmp_map.log[key][i].v1 == o->v1)
            skip_this = 1;

      }
      
      if (!skip_this) {
      
        for (j = 0; j < len; ++j) {
    
          if (V0_HASDEP(deps_bitvec, j)) ++v0_count_deps;
          if (V1_HASDEP(deps_bitvec, j)) ++v1_count_deps;
      
        }

        for (idx = 0; idx < len && fails < 8; ++idx) {

          if (V0_HASDEP(deps_bitvec, idx)) {

            status = 0;
            if (unlikely(weizz_cmp_extend_encoding(h, o->v0, o->v1, idx, buf, len, 1, &status)))
              goto exit_weizz_cmp_fuzz;
            if (status == 2)
              ++fails;
            else if (status == 1)
              break;

          }

          if (V1_HASDEP(deps_bitvec, idx)) {
          
            status = 0;
            if (unlikely(weizz_cmp_extend_encoding(h, o->v1, o->v0, idx, buf, len, 1, &status)))
              goto exit_weizz_cmp_fuzz;
            if (status == 2)
              ++fails;
            else if (status == 1)
              break;

          }

        }
        
        // If failed, add to dictionary
        if (fails >= 8) {

          try_to_add_to_dict(o->v0, SHAPE_BYTES(h->shape));
          try_to_add_to_dict(o->v1, SHAPE_BYTES(h->shape));

        }
        
      }

      if (!skip_this && enable_locked_havoc && pass_stats[key].total == pass_stats[key].failed && status != 1) {
      
        if (v0_count_deps <= 1 && v1_count_deps <= 1) {
          // byte bruteforce
          
          sprintf(tmp, "brute %d/%d", sorted_cmps_idx, sorted_cmps_len);
          stage_short = "brute";
          stage_name = tmp;
          stage_max = stage_cur = 0;
          
          for (idx = 0; idx < len && status != 1; ++idx) {

            if ((V0_HASDEP(deps_bitvec, idx) || V1_HASDEP(deps_bitvec, idx)) && !GET_BIT(bruted_bits, idx))
              stage_max += 255;
              
          }
        
          for (idx = 0; idx < len && status != 1; ++idx) {

            if ((V0_HASDEP(deps_bitvec, idx) || V1_HASDEP(deps_bitvec, idx)) && !GET_BIT(bruted_bits, idx)) {
            
              SET_BIT(bruted_bits, idx);
            
              u8 saved = buf[idx];
              
              for (j = 0; j < 256 && status != 1; ++j) {
              
                if (saved == j) continue;
                
                stage_cur++;
                
                buf[idx] = j;
                if (unlikely(weizz_perform_fuzz(buf, len, &status)))
                  goto exit_weizz_cmp_fuzz;
              
              }

            }

          }
        
        } else {
        
          if (unlikely(locked_havoc(perf_score, key, deps_bitvec, buf, len, &status)))
            goto exit_weizz_cmp_fuzz;
        
        }
        
        sprintf(tmp, "cmp %d/%d", sorted_cmps_idx, sorted_cmps_len);
        stage_short = "cmp";
        stage_name = tmp;
        
        stage_max = loggeds;
      
      }

      if (ti && place_tags(h->id, len, deps_bitvec, ti, is_i2s, is_checksum, checksum_coverage))
        last_cmp_that_placed_tag = key;

    }
    
    if (status == 1)
      found = 1;

  }
  
  r = 0;

  if (!skip_cmp && pass_stats[key].total < 255)
    pass_stats[key].total++;
  if (!skip_cmp && !found && pass_stats[key].failed < 255)
    pass_stats[key].failed++;

exit_weizz_cmp_fuzz:

  for (i = 0; i < loggeds; ++i) {
  
    if (DEPS_EXISTS(key, i)) {

      u8 *deps_bitvec = DEPS_GET(key, i);
      DEPS_GET(key, i) = NULL;
      ck_free(deps_bitvec);
    
    }

  }

  return r;

}

void weizz_cmp_checksum_preprocess(u32 key, u8 *buf, u32 len, u16 *checksum_coverage, u8* is_i2s_p, u8* is_cksum_p) {

  struct cmp_header* h = &orig_cmp_map.headers[key];
  u32 i, j, idx;

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_H) loggeds = CMP_MAP_H;
  
  u8 is_checksum = 0;

  u8 *v0_total_deps = ck_alloc((len >> 3) + 1);
  u8 *v1_total_deps = ck_alloc((len >> 3) + 1);

  u32 v0_deps_counter, v1_deps_counter;

  for (i = 0; i < loggeds; ++i) {

    if (DEPS_EXISTS(key, i)) {

      u8 *deps_bitvec = DEPS_GET(key, i);

      v0_deps_counter = 0;
      v1_deps_counter = 0;

      u8 v0_input_to_state_type = 0;
      u8 v1_input_to_state_type = 0;
      u8 v0_todo = 3, v1_todo = 3;

      u64 overlapping_deps = 0;

      for (j = 0; j < len; ++j) {

        if (ANY_V0_HASDEP(deps_bitvec, j)) {

          if (ANY_V1_HASDEP(deps_bitvec, j)) {
            if (!(j == 0 || !ANY_V1_HASDEP(deps_bitvec, j-1)) ||
                !(j == len-1 || !ANY_V1_HASDEP(deps_bitvec, j+1)))
               overlapping_deps++;
          }

          ++v0_deps_counter;
          SET_BIT(v0_total_deps, j);

          if (v0_todo) {

            if ((orig_cmp_map.log[key][i].v0 & 0xff) == buf[j]) {

              v0_input_to_state_type = CKTYPE_NORMAL8 | CK_IS_LEFT;
              if (j + sizeof(u16) <= len &&
                  (orig_cmp_map.log[key][i].v0 & 0xffff) == *(u16 *)&buf[j]) {

                v0_input_to_state_type = CKTYPE_NORMAL16 | CK_IS_LEFT;
                if (j + sizeof(u32) <= len &&
                    (orig_cmp_map.log[key][i].v0 & 0xffffffff) ==
                        *(u32 *)&buf[j]) {

                  v0_input_to_state_type = CKTYPE_NORMAL32 | CK_IS_LEFT;
                  if (j + sizeof(u64) <= len &&
                      orig_cmp_map.log[key][i].v0 == *(u64 *)&buf[j]) {

                    v0_input_to_state_type = CKTYPE_NORMAL64 | CK_IS_LEFT;

                  }
                  
                }

              }

            }

            if (j + sizeof(u16) <= len &&
                SWAP16(orig_cmp_map.log[key][i].v0 & 0xffff) == *(u16 *)&buf[j])
              v0_input_to_state_type = CKTYPE_SWAP16 | CK_IS_LEFT;
            if (j + sizeof(u32) <= len &&
                SWAP32(orig_cmp_map.log[key][i].v0 & 0xffffffff) ==
                    *(u32 *)&buf[j]) {

              v0_input_to_state_type = CKTYPE_SWAP32 | CK_IS_LEFT;

            }

            if (j + sizeof(u64) <= len &&
                SWAP64(orig_cmp_map.log[key][i].v0) == *(u64 *)&buf[j]) {

              v0_input_to_state_type = CKTYPE_SWAP64 | CK_IS_LEFT;

            }

            v0_todo--;

          }

        }

        if (ANY_V1_HASDEP(deps_bitvec, j)) {

          ++v1_deps_counter;
          SET_BIT(v1_total_deps, j);

          if (v1_todo) {

            if ((orig_cmp_map.log[key][i].v1 & 0xff) == buf[j]) {

              v1_input_to_state_type = CKTYPE_NORMAL8 | CK_IS_RIGHT;
              if (j + sizeof(u16) <= len &&
                  (orig_cmp_map.log[key][i].v1 & 0xffff) == *(u16 *)&buf[j]) {

                v1_input_to_state_type = CKTYPE_NORMAL16 | CK_IS_RIGHT;
                if (j + sizeof(u32) <= len &&
                    (orig_cmp_map.log[key][i].v1 & 0xffffffff) ==
                        *(u32 *)&buf[j]) {

                  v1_input_to_state_type = CKTYPE_NORMAL32 | CK_IS_RIGHT;
                  if (j + sizeof(u64) <= len &&
                      orig_cmp_map.log[key][i].v1 == *(u64 *)&buf[j]) {

                    v1_input_to_state_type = CKTYPE_NORMAL64 | CK_IS_RIGHT;

                  }

                }

              }

            }

            if (j + sizeof(u16) <= len &&
                SWAP16(orig_cmp_map.log[key][i].v1 & 0xffff) == *(u16 *)&buf[j])
              v1_input_to_state_type = CKTYPE_SWAP16 | CK_IS_RIGHT;
            if (j + sizeof(u32) <= len &&
                SWAP32(orig_cmp_map.log[key][i].v1 & 0xffffffff) ==
                    *(u32 *)&buf[j]) {

              v1_input_to_state_type = CKTYPE_SWAP32 | CK_IS_RIGHT;

            }

            if (j + sizeof(u64) <= len &&
                SWAP64(orig_cmp_map.log[key][i].v1) == *(u64 *)&buf[j]) {

              v1_input_to_state_type = CKTYPE_SWAP64 | CK_IS_RIGHT;

            }

            v1_todo--;

          }

        }

      }
      
      if (v0_input_to_state_type)
        *is_i2s_p = IS_V0;
      if (v1_input_to_state_type)
        *is_i2s_p = IS_V1;
      
      if (checksums_info[h->id] != CK_NOT_UNDER_CONTROL &&
          /*!is_checksum &&*/ h->type == CMP_TYPE_INS) {

        if (checksums_info[h->id]) {
          
          if ((checksums_info[h->id] & CK_ARGTYPE_MASK) ==
              CK_IS_LEFT) {

            DBGPRINT("old v0 checksum!: %x (%lx %lx) %d    %d\n",
                     h->id, orig_cmp_map.log[key][i].v0,
                     orig_cmp_map.log[key][i].v1, checksums_info[h->id],
                     cmp_height_cnt);
            is_checksum = IS_V0;

          } else {

            DBGPRINT("old v1 checksum!: %x (%lx %lx) %d    %d\n",
                     h->id, orig_cmp_map.log[key][i].v0,
                     orig_cmp_map.log[key][i].v1, checksums_info[h->id],
                     cmp_height_cnt);
            is_checksum = IS_V1;

          }
          
          continue;
          
        }

        if (v0_deps_counter && v1_deps_counter && overlapping_deps <= CK_DEPS_OVERLAP_BOUND) {

          if (v0_input_to_state_type && !v1_input_to_state_type &&
              !(v0_input_to_state_type & CKTYPE_NORMAL8)
              && v1_deps_counter > 2) {

            if (!checksums_info[h->id]) {

              patched_cksums_num++;
              patched_cksums_total_num++;

            }

            checksums_info[h->id] = v0_input_to_state_type;
            is_checksum            = IS_V0;

            cksum_found = new_cksum_found = 1;

            DBGPRINT("new v0 checksum!: %x (%lx %lx) %d    %d\n",
                     h->id, orig_cmp_map.log[key][i].v0,
                     orig_cmp_map.log[key][i].v1,
                     checksums_info[h->id], cmp_height_cnt);
            continue;

          } else if (!v0_input_to_state_type && v1_input_to_state_type &&

                     !(v1_input_to_state_type & CKTYPE_NORMAL8)
                     && v0_deps_counter > 2) {

            if (!checksums_info[h->id]) {

              patched_cksums_num++;
              patched_cksums_total_num++;

            }

            checksums_info[h->id] = v1_input_to_state_type;
            is_checksum            = IS_V1;

            cksum_found = new_cksum_found = 1;

            DBGPRINT("new v1 checksum!: %x (%lx %lx) %d    %d\n",
                     h->id, orig_cmp_map.log[key][i].v0,
                     orig_cmp_map.log[key][i].v1,
                     checksums_info[h->id], cmp_height_cnt);
            continue;

          }
        }
      }
    }
  }
  
  *is_cksum_p = is_checksum;
  
  for (i = 0; i < len; ++i) {

    if (GET_BIT(v0_total_deps, i)) {

      if (is_checksum & IS_V1)
        checksum_coverage[i] = h->id;

    } else if (GET_BIT(v1_total_deps, i)) {

      if (is_checksum & IS_V0)
        checksum_coverage[i] = h->id;

    }

  }
  
  ck_free(v1_total_deps);
  ck_free(v0_total_deps);
  
}

u8 surgical_fuzzing(u32 perf_score, u8 *buf, u32 len,
                    struct tags_info** p_ti, u32 *covered_by_tags) {

  u8  r = 1;
  s32 i;

  stage_cur_byte = -1;
  
  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs = total_execs;
  orig_hit_cnt = queued_paths + unique_crashes;
  
  /* Sort CMPs based on the counter */
  
  static u16 sorted_cmps[CMP_MAP_W];
  sorted_cmps_len = 0;

  for (i = 0; i < CMP_MAP_W; ++i) {

    if (likely(!weizz_deps[i])) continue;
    
    struct cmp_header* o_h = &orig_cmp_map.headers[i];
    
    if (likely(!o_h->hits)) continue;
    
    tags_counters[o_h->id] = MIN(tags_counters[o_h->id], o_h->cnt);

    o_h->cnt = tags_counters[o_h->id];
    
    sorted_cmps[sorted_cmps_len++] = (u16)i;

  }
  
  qsort_r(sorted_cmps, sorted_cmps_len, sizeof(u16), compare_header_counter,
          &orig_cmp_map);
  
  u16 * checksum_coverage = ck_alloc(sizeof(u16) * len);
  u8 * is_checksum = ck_alloc(sorted_cmps_len);
  u8 * is_i2s = ck_alloc(sorted_cmps_len);
   
  for (sorted_cmps_idx = 0; sorted_cmps_idx < sorted_cmps_len; ++sorted_cmps_idx) {
  
    i = sorted_cmps[sorted_cmps_idx];
    
    weizz_cmp_checksum_preprocess(i, buf, len, checksum_coverage, is_i2s + sorted_cmps_idx, is_checksum + sorted_cmps_idx);

  }

  *p_ti = ck_alloc(sizeof(struct tags_info) + sizeof(struct tag) * len);

  last_cmp_that_placed_tag = 0;
  
  u8* bruted_bits = ck_alloc(len >> 3);
  
  /*stage_name = "surgical";
  stage_short = "surgical";
  stage_max = sorted_cmps_len;
  stage_cur = 0;*/
  
  for (sorted_cmps_idx = 0; sorted_cmps_idx < sorted_cmps_len; ++sorted_cmps_idx) {

    i = sorted_cmps[sorted_cmps_idx];
    
    if (weizz_cmp_fuzz(perf_score, i, buf, len, *p_ti, bruted_bits, checksum_coverage, is_i2s[sorted_cmps_idx], is_checksum[sorted_cmps_idx]))
      goto exit_surgical_fuzz;

    ck_free(weizz_deps[i]);
    weizz_deps[i] = NULL;

  }
  
  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ITS] += total_execs - orig_execs;

  write_pass_stats();

  /* Calcuate tags coverage */

  *covered_by_tags = 0;
  (*p_ti)->max_counter = 0;
  (*p_ti)->ntypes = 0; //NEW ntypes
  s32 last_tg = -1;

  for (i = 0; i < len; ++i) {

    if ((*p_ti)->tags[i].cmp_id != last_tg) ++(*p_ti)->ntypes;
    last_tg = (*p_ti)->tags[i].cmp_id;

    if ((*p_ti)->tags[i].cmp_id != 0) {
      (*covered_by_tags)++;
      (*p_ti)->max_counter = MAX((*p_ti)->max_counter, (*p_ti)->tags[i].counter);
    }

  }

  // DBGPRINT(" covered by tags: %d / %d\n", (*covered_by_tags), len);

  r = 0;

exit_surgical_fuzz:

  ck_free(is_checksum);
  ck_free(is_i2s);

  ck_free(bruted_bits);
  ck_free(checksum_coverage);

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ITS] += total_execs - orig_execs;

  if (r) {
  
    for (i = 0; i < CMP_MAP_W; ++i) {

      if (likely(!weizz_deps[i])) continue;
      ck_free(weizz_deps[i]);
      weizz_deps[i] = NULL;
      
    }

    ck_free((*p_ti));
    *p_ti = NULL;

  }

  return r;

}

u8 weizz_first_stage(u32 perf_score, u8 *buf, u32 len) {

  u8 r = 1;

  u32 covered_by_tags;
  struct tags_info *ti = NULL;

  u8 must_add_to_tg_queue = queue_cur->tags_fname == NULL;
  queue_cur->use_derived_tags = 0;
  
  if (must_add_to_tg_queue)
    queue_cur->tags_fname =
        alloc_printf("%s/tags/%s", out_dir, strrchr(queue_cur->fname, '/') + 1);

  if (queue_cur->sync_tags_fname) {

    ck_free(queue_cur->sync_tags_fname);
    queue_cur->sync_tags_fname = NULL;

  }

  if (queue_cur->sync_fname) {

    ck_free(queue_cur->sync_fname);
    queue_cur->sync_fname = NULL;

  }

  if (weizz_colorization(buf, len, queue_cur->exec_cksum)) {
    memset(cmp_map->headers, 0, sizeof(cmp_map->headers));
    goto exit_first_stage;
  }
  
  memset(cmp_map->headers, 0, sizeof(cmp_map->headers));

  u64 old_checksums_num = patched_cksums_num;

  if (get_deps(buf, len))
    goto exit_first_stage;
  
  if (surgical_fuzzing(perf_score, buf, len, &ti, &covered_by_tags))
    goto exit_first_stage;

  if (enable_checksum_recovery && old_checksums_num != patched_cksums_num)
    must_getdeps_asap = 3;

  if (ti) {

    queue_cur->tags_coverage = (double)(covered_by_tags) / len;
    
    max_tags_coverage = MAX(queue_cur->tags_coverage, max_tags_coverage);
      
    global_max_counter = MAX(global_max_counter, ti->max_counter);
    
    if (queue_cur->passed_getdeps && queue_cur->cached_tags_ntypes) {

      /* Update */
      tags_ntypes_avg = (tags_ntypes_count * tags_ntypes_avg -
                         queue_cur->cached_tags_ntypes + ti->ntypes) /
                        tags_ntypes_count;

    } else {

      /* Add */
      tags_ntypes_avg = (tags_ntypes_count * tags_ntypes_avg + ti->ntypes) /
                        (tags_ntypes_count + 1);
      ++tags_ntypes_count;

    }

    queue_cur->cached_tags_ntypes = ti->ntypes;
    queue_cur->cached_max_counter = ti->max_counter;
    
    /* Fix checksums here, wrong fixes produce invalid entries only here */

    // cmp_cur = -1;

    if (enable_checksum_recovery && cksum_found) {

      if (patched_cksums_num) {  // queue_cur->must_fix_checksums) {

        u32 ck_count;

        if (fix_checksums(queue_cur->exec_cksum, ti, buf, queue_cur->len,
                          &ck_count, 0)) {

          queue_cur->is_invalid = 1;
          DBGPRINT("\n");
          DBGPRINT(" FAILED TO FIX CHECKSUMS\n");
          DBGPRINT("\n");

        } else {
        
          if (ck_count) {

            s32 fd;

            unlink(queue_cur->fname);                      /* ignore errors */

            fd = locked_open_mode(queue_cur->fname, O_WRONLY | O_CREAT | O_EXCL,
                                  0600);

            if (fd < 0) PFATAL("Unable to create '%s'", queue_cur->fname);

            ck_write(fd, buf, queue_cur->len, queue_cur->fname);
            close(fd);

          }

          ++getdeps_fix;

          DBGPRINT("\n");
          DBGPRINT(" CHECKSUMS OKKKKKK\n");
          DBGPRINT("\n");

        }

        getdeps_fix_total++;

      } else {

        memcpy(cmp_patch_map, cmp_patch_local_map, CMP_MAP_W);

      }

      queue_cur->must_fix_checksums = 0;

      if (cksum_found) { // TODO is it needed?

        cksum_patched = 1;
        if (new_cksum_found) {

          must_getdeps_asap = 3;
          new_cksum_found   = 0;

        }

      }

    }

    if (cksum_found) write_patch_map();
      
    s32 tags_fd = locked_open_mode(queue_cur->tags_fname, O_WRONLY | O_TRUNC | O_CREAT, 0600);
    ck_write(tags_fd, ti, sizeof(struct tags_info) + sizeof(struct tag) * len, queue_cur->tags_fname);
    close(tags_fd);

    if (must_add_to_tg_queue) add_to_tg_queue(queue_cur);

    struct queue_entry *qptr = tg_queue;
    do {

      if (qptr->tags_fname != queue_cur->tags_fname || qptr == queue_cur) continue;

      qptr->cached_tags_ntypes = ti->ntypes;
      qptr->tags_coverage = queue_cur->tags_coverage;

      qptr->tags_fname =
          alloc_printf("%s/tags/%s", out_dir, strrchr(qptr->fname, '/') + 1);

      tags_fd = locked_open_mode(qptr->tags_fname, O_WRONLY | O_TRUNC  | O_CREAT, 0600);
      if (tags_fd < 0 || write(tags_fd, ti, sizeof(struct tags_info) + sizeof(struct tag) * qptr->len) != sizeof(struct tags_info) + sizeof(struct tag) * qptr->len) {

        qptr->cached_tags_ntypes = 0;
        qptr->tags_coverage = 0;
        qptr->use_derived_tags = 0;
        ck_free(qptr->tags_fname);
        qptr->tags_fname = NULL;

      }
      
      close(tags_fd);

    } while ((qptr = qptr->tg_next));

    r = 0;
    ck_free(ti);

  }

exit_first_stage:

  if (r) {

    if (queue_cur->tags_fname) {

      struct queue_entry *qptr = queue_cur;
      while ((qptr = qptr->next)) {

        if (qptr->tags_fname != queue_cur->tags_fname) break;

        qptr->use_derived_tags = 0;
        qptr->tags_fname      = NULL;

      }

      // todo verify
      ck_free(queue_cur->tags_fname);

      queue_cur->tags_fname = NULL;

    }

  }

  queue_cur->passed_getdeps = 1;

  return r;

}

struct tags_info* produce_checksums_tags(u8* buf, u32 len) {

  u32 i, j;

  memset(cmp_map->headers, 0, sizeof(cmp_map->headers));

  //if (weizz_colorization(buf, len, queue_cur->exec_cksum))
  //  return NULL;

  if (get_deps(buf, len))
    return NULL;
    
  static u16 sorted_cmps[CMP_MAP_W];
  sorted_cmps_len = 0;

  for (i = 0; i < CMP_MAP_W; ++i) {

    if (likely(!weizz_deps[i])) continue;
    
    struct cmp_header* o_h = &orig_cmp_map.headers[i];
    
    if (likely(!o_h->hits)) continue;
    
    tags_counters[o_h->id] = MIN(tags_counters[o_h->id], o_h->cnt);

    o_h->cnt = tags_counters[o_h->id];
    
    sorted_cmps[sorted_cmps_len++] = (u16)i;

  }
  
  qsort_r(sorted_cmps, sorted_cmps_len, sizeof(u16), compare_header_counter,
          &orig_cmp_map);
  
  u16 * checksum_coverage = ck_alloc(sizeof(u16) * len);
  u8 * is_checksum = ck_alloc(sorted_cmps_len);
  u8 * is_i2s = ck_alloc(sorted_cmps_len);
  
  for (sorted_cmps_idx = 0; sorted_cmps_idx < sorted_cmps_len; ++sorted_cmps_idx) {
  
    i = sorted_cmps[sorted_cmps_idx];
    
    weizz_cmp_checksum_preprocess(i, buf, len, checksum_coverage, is_i2s + sorted_cmps_idx, is_checksum + sorted_cmps_idx);

  }

  struct tags_info *ti = ck_alloc(sizeof(struct tags_info) + sizeof(struct tag) * len);
  
  skip_surgical = 1;
  
  for (sorted_cmps_idx = 0; sorted_cmps_idx < sorted_cmps_len; ++sorted_cmps_idx) {

    i = sorted_cmps[sorted_cmps_idx];
    
    if (weizz_cmp_fuzz(0, i, buf, len, ti, NULL, checksum_coverage, is_i2s[sorted_cmps_idx], is_checksum[sorted_cmps_idx])) {
      ck_free(ti);
      ti = NULL;
      goto exit_produce_tags;
    }

    ck_free(weizz_deps[i]);
    weizz_deps[i] = NULL;

  }

exit_produce_tags:

  ck_free(is_checksum);
  ck_free(is_i2s);

  skip_surgical = 0;
  ck_free(checksum_coverage);

  return ti;

}


