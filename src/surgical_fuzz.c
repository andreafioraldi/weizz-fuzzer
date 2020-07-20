/*
   weizz - surgical fuzz of a comparison
   -------------------------------------

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

#define CK_DEPS_OVERLAP_BOUND 0

static size_t u64_to_str(char *buf, u64 i) {

  return sprintf(buf, "%lld", i);

}

void weizz_cmp_checksum_preprocess(u8 *out_buf, u32 len, u16 *checksum_coverage) {

  s32 i, j;
  
  u8 is_checksum       = 0;

  u8 *v0_total_deps = ck_alloc((len >> 3) + 1);
  u8 *v1_total_deps = ck_alloc((len >> 3) + 1);

  struct cmp_operands* col = orig_wmap.log[cmp_cur];

  u32 v0_deps_counter, v1_deps_counter;

  for (cmp_height_idx = cmp_height_cnt - 1; cmp_height_idx >= 0;
       --cmp_height_idx) {

    if (DEPS_EXISTS(cmp_cur, cmp_height_idx)) {

      u8 *deps_bitvec = DEPS_GET(cmp_cur, cmp_height_idx);

      v0_deps_counter = 0;
      v1_deps_counter = 0;

      u8 v0_input_to_state_type = 0;
      u8 v1_input_to_state_type = 0;
      u8 v0_todo = 3, v1_todo = 3;

      u64 overlapping_deps = 0;

      for (i = 0; i < len; ++i) {

        if (ANY_V0_HASDEP(deps_bitvec, i)) {

          if (ANY_V1_HASDEP(deps_bitvec, i)) {
            if (!(i == 0 || !ANY_V1_HASDEP(deps_bitvec, i-1)) ||
                !(i == len-1 || !ANY_V1_HASDEP(deps_bitvec, i+1)))
               overlapping_deps++;
          }

          ++v0_deps_counter;
          SET_BIT(v0_total_deps, i);

          if (v0_todo) {

            if ((col[cmp_height_idx].v0 & 0xff) == out_buf[i]) {

              v0_input_to_state_type = CKTYPE_NORMAL8 | CK_IS_LEFT;
              if (i + sizeof(u16) <= len &&
                  (col[cmp_height_idx].v0 & 0xffff) == *(u16 *)&out_buf[i]) {

                v0_input_to_state_type = CKTYPE_NORMAL16 | CK_IS_LEFT;
                if (i + sizeof(u32) <= len &&
                    (col[cmp_height_idx].v0 & 0xffffffff) ==
                        *(u32 *)&out_buf[i]) {

                  v0_input_to_state_type = CKTYPE_NORMAL32 | CK_IS_LEFT;
                  if (i + sizeof(u64) <= len &&
                      col[cmp_height_idx].v0 == *(u64 *)&out_buf[i]) {

                    v0_input_to_state_type = CKTYPE_NORMAL64 | CK_IS_LEFT;
                    maybe_add_auto(&out_buf[i], sizeof(u64));

                  } else

                    maybe_add_auto(&out_buf[i], sizeof(u32));

                }

              }

            }

            if (i + sizeof(u16) <= len &&
                SWAP16(col[cmp_height_idx].v0 & 0xffff) == *(u16 *)&out_buf[i])
              v0_input_to_state_type = CKTYPE_SWAP16 | CK_IS_LEFT;
            if (i + sizeof(u32) <= len &&
                SWAP32(col[cmp_height_idx].v0 & 0xffffffff) ==
                    *(u32 *)&out_buf[i]) {

              v0_input_to_state_type = CKTYPE_SWAP32 | CK_IS_LEFT;
              maybe_add_auto(&out_buf[i], sizeof(u32));

            }

            if (i + sizeof(u64) <= len &&
                SWAP64(col[cmp_height_idx].v0) == *(u64 *)&out_buf[i]) {

              v0_input_to_state_type = CKTYPE_SWAP64 | CK_IS_LEFT;
              maybe_add_auto(&out_buf[i], sizeof(u64));

            }

            v0_todo--;

          }

        }

        if (ANY_V1_HASDEP(deps_bitvec, i)) {

          ++v1_deps_counter;
          SET_BIT(v1_total_deps, i);

          if (v1_todo) {

            if ((col[cmp_height_idx].v1 & 0xff) == out_buf[i]) {

              v1_input_to_state_type = CKTYPE_NORMAL8 | CK_IS_RIGHT;
              if (i + sizeof(u16) <= len &&
                  (col[cmp_height_idx].v1 & 0xffff) == *(u16 *)&out_buf[i]) {

                v1_input_to_state_type = CKTYPE_NORMAL16 | CK_IS_RIGHT;
                if (i + sizeof(u32) <= len &&
                    (col[cmp_height_idx].v1 & 0xffffffff) ==
                        *(u32 *)&out_buf[i]) {

                  v1_input_to_state_type = CKTYPE_NORMAL32 | CK_IS_RIGHT;
                  if (i + sizeof(u64) <= len &&
                      col[cmp_height_idx].v1 == *(u64 *)&out_buf[i]) {

                    v1_input_to_state_type = CKTYPE_NORMAL64 | CK_IS_RIGHT;
                    maybe_add_auto(&out_buf[i], sizeof(u64));

                  } else

                    maybe_add_auto(&out_buf[i], sizeof(u32));

                }

              }

            }

            if (i + sizeof(u16) <= len &&
                SWAP16(col[cmp_height_idx].v1 & 0xffff) == *(u16 *)&out_buf[i])
              v1_input_to_state_type = CKTYPE_SWAP16 | CK_IS_RIGHT;
            if (i + sizeof(u32) <= len &&
                SWAP32(col[cmp_height_idx].v1 & 0xffffffff) ==
                    *(u32 *)&out_buf[i]) {

              v1_input_to_state_type = CKTYPE_SWAP32 | CK_IS_RIGHT;
              maybe_add_auto(&out_buf[i], sizeof(u32));

            }

            if (i + sizeof(u64) <= len &&
                SWAP64(col[cmp_height_idx].v1) == *(u64 *)&out_buf[i]) {

              v1_input_to_state_type = CKTYPE_SWAP64 | CK_IS_RIGHT;
              maybe_add_auto(&out_buf[i], sizeof(u64));

            }

            v1_todo--;

          }

        }

      }
      
      if (checksums_info[cmp_cur_head.id] != CK_NOT_UNDER_CONTROL &&
          /*!is_checksum &&*/ cmp_cur_head.type == CMP_TYPE_INS) {

        if (checksums_info[cmp_cur_head.id]) {
          
          if ((checksums_info[cmp_cur_head.id] & CK_ARGTYPE_MASK) ==
              CK_IS_LEFT) {

            DBGPRINT("old v0 checksum!: %x (%lx %lx) %d    %d\n",
                     cmp_cur_head.id, col[cmp_height_idx].v0,
                     col[cmp_height_idx].v1, checksums_info[cmp_cur_head.id],
                     cmp_height_cnt);
            is_checksum            = IS_V0;

          } else {

            DBGPRINT("old v1 checksum!: %x (%lx %lx) %d    %d\n",
                     cmp_cur_head.id, col[cmp_height_idx].v0,
                     col[cmp_height_idx].v1, checksums_info[cmp_cur_head.id],
                     cmp_height_cnt);
            is_checksum            = IS_V1;

          }
          
          continue;
          
        }

        if (v0_deps_counter && v1_deps_counter && overlapping_deps <= CK_DEPS_OVERLAP_BOUND) {

          if (v0_input_to_state_type && !v1_input_to_state_type &&
              !(v0_input_to_state_type & CKTYPE_NORMAL8)
              && v1_deps_counter > 2) {

            if (!checksums_info[cmp_cur_head.id]) {

              patched_cksums_num++;
              patched_cksums_total_num++;

            }

            checksums_info[cmp_cur_head.id] = v0_input_to_state_type;
            is_checksum            = IS_V0;

            cksum_found = new_cksum_found = 1;

            DBGPRINT("new v0 checksum!: %x (%lx %lx) %d    %d\n",
                     cmp_cur_head.id, col[cmp_height_idx].v0,
                     col[cmp_height_idx].v1,
                     checksums_info[cmp_cur_head.id], cmp_height_cnt);
            continue;

          } else if (!v0_input_to_state_type && v1_input_to_state_type &&

                     !(v1_input_to_state_type & CKTYPE_NORMAL8)
                     && v0_deps_counter > 2) {

            if (!checksums_info[cmp_cur_head.id]) {

              patched_cksums_num++;
              patched_cksums_total_num++;

            }

            checksums_info[cmp_cur_head.id] = v1_input_to_state_type;
            is_checksum            = IS_V1;

            cksum_found = new_cksum_found = 1;

            DBGPRINT("new v1 checksum!: %x (%lx %lx) %d    %d\n",
                     cmp_cur_head.id, col[cmp_height_idx].v0,
                     col[cmp_height_idx].v1,
                     checksums_info[cmp_cur_head.id], cmp_height_cnt);
            continue;

          }
        }
      }
    }
  }
  
  for (i = 0; i < len; ++i) {

    if (GET_BIT(v0_total_deps, i)) {

      if (is_checksum & IS_V1)
        checksum_coverage[i] = cmp_cur_head.id;

    } else if (GET_BIT(v1_total_deps, i)) {

      if (is_checksum & IS_V0)
        checksum_coverage[i] = cmp_cur_head.id;

    }

  }
  
  ck_free(v1_total_deps);
  ck_free(v0_total_deps);
  
}




u8 place_tags(u32 len, u8* deps_bitvec, tags_info_t* tags, u8 is_checksum, u8 is_input_to_state, u16* checksum_coverage) {

  u32 locked_bytes = 0, v0_locked_bytes = 0, v1_locked_bytes = 0;
  u8 has_placed_tag = 0;
  s32 i;
  
  /*if (!is_checksum && checksums_info[cmp_cur_head.id] && checksums_info[cmp_cur_head.id] != CK_NOT_UNDER_CONTROL) { //redundancy
  
    if ((checksums_info[cmp_cur_head.id] & CK_ARGTYPE_MASK) == CK_IS_LEFT)
      is_checksum = IS_V0;
    else
      is_checksum = IS_V1;
  
  }*/

  for (i = 0; i < len; ++i) {

    if (V0_HASDEP(deps_bitvec, i)) {

      ++v0_locked_bytes;
      ++locked_bytes;

      if (V1_HASDEP(deps_bitvec, i)) { ++v1_locked_bytes; }

    } else if (V1_HASDEP(deps_bitvec, i)) {

      ++v1_locked_bytes;
      ++locked_bytes;

    }

  }
  
  if (v0_locked_bytes <= 1 && v1_locked_bytes <= 1) return 0;

  u8 v0_brothers    = MIN(v0_locked_bytes, 255);
  u8 v1_brothers    = MIN(v1_locked_bytes, 255);

  for (i = 0; i < len; ++i) {

    if (V0_HASDEP(deps_bitvec, i)) {

      if (V1_HASDEP(deps_bitvec, i)) {

        // Prioritize checksum related cmp or use a rate
        if (is_checksum & IS_V1 || !tags->tags[i].cmp_id ||
            ((v1_brothers < tags->tags[i].brothers &&
             tags->tags[i].brothers > 4) &&
             !(tags->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

          if ((i == 0 || tags->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !V1_HASDEP(deps_bitvec, i+1)))
          continue;

          tags->tags[i].cmp_id  = cmp_cur_head.id;
          tags->tags[i].parent  = last_cmp_that_placed_tag;
          tags->tags[i].counter = cmp_cur_head.cnt;
          tags->tags[i].flags   = tags->tags[i].flags & TAG_IS_LEN;
          tags->tags[i].flags |=
              (is_input_to_state & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
          tags->tags[i].brothers = v1_brothers;
          has_placed_tag         = 1;

          if (checksum_coverage[i]) {

            tags->tags[i].depends_on = checksum_coverage[i];

          }

          if (is_checksum == IS_V1) {

            tags->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

          }

        }

      }

      // Prioritize checksum related cmp or use a rate
      if (is_checksum & IS_V0 || !tags->tags[i].cmp_id ||
          (v0_brothers < tags->tags[i].brothers && tags->tags[i].brothers > 4 &&
           !(tags->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || tags->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !V0_HASDEP(deps_bitvec, i+1)))
          continue;

        tags->tags[i].cmp_id  = cmp_cur_head.id;
        tags->tags[i].parent  = last_cmp_that_placed_tag;
        tags->tags[i].counter = cmp_cur_head.cnt;
        tags->tags[i].flags   = tags->tags[i].flags & TAG_IS_LEN;
        tags->tags[i].flags |= TAG_CMP_IS_LEFT;
        tags->tags[i].flags |=
            (is_input_to_state & IS_V0) ? TAG_IS_INPUT_TO_STATE : 0;
        tags->tags[i].brothers = v0_brothers;
        has_placed_tag         = 1;

        if (checksum_coverage[i]) {

          tags->tags[i].depends_on = checksum_coverage[i];

        }

        if (is_checksum == IS_V0) {

          tags->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

        }

      }

    } else if (V1_HASDEP(deps_bitvec, i)) {

      // Prioritize checksum related cmp or use a rate
      if (is_checksum & IS_V1 || !tags->tags[i].cmp_id ||
          (v1_brothers < tags->tags[i].brothers && tags->tags[i].brothers > 4 &&
           !(tags->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || tags->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !V1_HASDEP(deps_bitvec, i+1)))
          continue;

        tags->tags[i].cmp_id  = cmp_cur_head.id;
        tags->tags[i].parent  = last_cmp_that_placed_tag;
        tags->tags[i].counter = cmp_cur_head.cnt;
        tags->tags[i].flags   = tags->tags[i].flags & TAG_IS_LEN;
        tags->tags[i].flags |=
            (is_input_to_state & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
        tags->tags[i].brothers = v1_brothers;
        has_placed_tag         = 1;

        if (checksum_coverage[i]) {

          tags->tags[i].depends_on = checksum_coverage[i];

        }

        if (is_checksum == IS_V1) {

          tags->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

        }

      }

    }

  }
  
  //TODO optimize do in a single loop
  //IMPL has less priority
  
  locked_bytes = v0_locked_bytes = v1_locked_bytes = 0;

  for (i = 0; i < len; ++i) {

    if (IMPL_V0_HASDEP(deps_bitvec, i)) {

      ++v0_locked_bytes;
      ++locked_bytes;

      if (IMPL_V1_HASDEP(deps_bitvec, i)) { ++v1_locked_bytes; }

    } else if (IMPL_V1_HASDEP(deps_bitvec, i)) {

      ++v1_locked_bytes;
      ++locked_bytes;

    }

  }

  v0_brothers    = MIN(v0_locked_bytes, 255);
  v1_brothers    = MIN(v1_locked_bytes, 255);

  for (i = 0; i < len; ++i) {

    if (IMPL_V0_HASDEP(deps_bitvec, i)) {

      if (IMPL_V1_HASDEP(deps_bitvec, i)) {

        // Prioritize checksum related cmp or use a rate
        if (is_checksum & IS_V1 || !tags->tags[i].cmp_id ||
            ((v1_brothers < tags->tags[i].brothers &&
             tags->tags[i].brothers > 4) &&
             !(tags->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

          if ((i == 0 || tags->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !IMPL_V1_HASDEP(deps_bitvec, i+1)))
          continue;

          tags->tags[i].cmp_id  = cmp_cur_head.id;
          tags->tags[i].parent  = last_cmp_that_placed_tag;
          tags->tags[i].counter = cmp_cur_head.cnt;
          tags->tags[i].flags   = tags->tags[i].flags & TAG_IS_LEN;
          tags->tags[i].flags |=
              (is_input_to_state & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
          tags->tags[i].brothers = v1_brothers;
          has_placed_tag         = 1;

          if (checksum_coverage[i]) {

            tags->tags[i].depends_on = checksum_coverage[i];

          }

          if (is_checksum == IS_V1) {

            tags->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

          }

        }

      }

      // Prioritize checksum related cmp or use a rate
      if (is_checksum & IS_V0 || !tags->tags[i].cmp_id ||
          (v0_brothers < tags->tags[i].brothers && tags->tags[i].brothers > 4 &&
           !(tags->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || tags->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !IMPL_V0_HASDEP(deps_bitvec, i+1)))
          continue;

        tags->tags[i].cmp_id  = cmp_cur_head.id;
        tags->tags[i].parent  = last_cmp_that_placed_tag;
        tags->tags[i].counter = cmp_cur_head.cnt;
        tags->tags[i].flags   = tags->tags[i].flags & TAG_IS_LEN;
        tags->tags[i].flags |= TAG_CMP_IS_LEFT;
        tags->tags[i].flags |=
            (is_input_to_state & IS_V0) ? TAG_IS_INPUT_TO_STATE : 0;
        tags->tags[i].brothers = v0_brothers;
        has_placed_tag         = 1;

        if (checksum_coverage[i]) {

          tags->tags[i].depends_on = checksum_coverage[i];

        }

        if (is_checksum == IS_V0) {

          tags->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

        }

      }

    } else if (IMPL_V1_HASDEP(deps_bitvec, i)) {

      // Prioritize checksum related cmp or use a rate
      if (is_checksum & IS_V1 || !tags->tags[i].cmp_id ||
          (v1_brothers < tags->tags[i].brothers && tags->tags[i].brothers > 4 &&
           !(tags->tags[i].flags & TAG_CMP_IS_CHECKSUM))) {

        if ((i == 0 || tags->tags[i-1].cmp_id !=
              cmp_cur_head.id) && (i == len-1 || !IMPL_V1_HASDEP(deps_bitvec, i+1)))
          continue;

        tags->tags[i].cmp_id  = cmp_cur_head.id;
        tags->tags[i].parent  = last_cmp_that_placed_tag;
        tags->tags[i].counter = cmp_cur_head.cnt;
        tags->tags[i].flags   = tags->tags[i].flags & TAG_IS_LEN;
        tags->tags[i].flags |=
            (is_input_to_state & IS_V1) ? TAG_IS_INPUT_TO_STATE : 0;
        tags->tags[i].brothers = v1_brothers;
        has_placed_tag         = 1;

        if (checksum_coverage[i]) {

          tags->tags[i].depends_on = checksum_coverage[i];

        }

        if (is_checksum == IS_V1) {

          tags->tags[i].flags |= TAG_CMP_IS_CHECKSUM;

        }

      }

    }

  }
  
  return has_placed_tag;

}



s32 weizz_perform_fuzz(u32 idx, u32 size, u8 *out_buf, u32 len) {

  u64 prev_queued, orig_hit_cnt, new_hit_cnt;
  s32 i;

  prev_queued  = queued_paths;
  orig_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(common_light_fuzz_stuff(out_buf, len))) return 1;

  new_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt)) {

    weizz_fuzz_found = 1;

    if (queued_paths != prev_queued) {

      if (surgical_use_derived_tags) {

        queue_top->use_derived_tags = 1;
        queue_top->tags_fname      = queue_cur->tags_fname;
        queue_top->parent          = queue_cur;

        add_to_tg_queue(queue_top);

      }

      queue_top->weizz_favored = ++weizz_pending_favored;

    }

    if (size >= MIN_AUTO_EXTRA && size <= MAX_AUTO_EXTRA) {

      maybe_add_auto(&out_buf[idx], size);

    }

  }

  return 0;

}

/* Fuzz a testcase in a surgical manner in order to bypass a target check */

u8 weizz_cmp_surgical_fuzz(u32 perf_score, u8 *out_buf, u32 len,
                           u8 skip_cmp_tries, tags_info_t *tags,
                           u16 *checksum_coverage) {

  u8 ret = 1;

  s32 i, j;
  u8 *saved_buf;
  u8  saved_brute;
  u64 prev_queued, orig_hit_cnt, new_hit_cnt, stage_orig_hit_cnt,
      stage_new_hit_cnt, prev_crashes;

  u8 is_checksum       = 0;
  u8 is_input_to_state = 0;
  
  u8 has_placed_tag = 0;

  u32 ck_lens[CMP_MAP_H];
  u32 ck_lens_idx = 0;

  u32 *mutables_idx_map;

  u8 *v0_total_deps = ck_alloc((len >> 3) + 1);
  u8 *v1_total_deps = ck_alloc((len >> 3) + 1);

  struct cmp_operands* col = orig_wmap.log[cmp_cur];

  weizz_fuzz_found = 0;

  u32 v0_deps_counter, v1_deps_counter;

  for (cmp_height_idx = cmp_height_cnt - 1; cmp_height_idx >= 0;
       --cmp_height_idx) {

    if (DEPS_EXISTS(cmp_cur, cmp_height_idx)) {

      u8 *deps_bitvec = DEPS_GET(cmp_cur, cmp_height_idx);
      
      v0_deps_counter = 0;
      v1_deps_counter = 0;

      u8 v0_input_to_state_type = 0;
      u8 v1_input_to_state_type = 0;
      u8 v0_todo = 3, v1_todo = 3;

      for (i = 0; i < len; ++i) {

        if (V0_HASDEP(deps_bitvec, i)) {

          ++v0_deps_counter;
          SET_BIT(v0_total_deps, i);

          if (v0_todo) {

            if ((col[cmp_height_idx].v0 & 0xff) == out_buf[i]) {

              v0_input_to_state_type = CKTYPE_NORMAL8 | CK_IS_LEFT;
              if (i + sizeof(u16) <= len &&
                  (col[cmp_height_idx].v0 & 0xffff) == *(u16 *)&out_buf[i]) {

                v0_input_to_state_type = CKTYPE_NORMAL16 | CK_IS_LEFT;
                if (i + sizeof(u32) <= len &&
                    (col[cmp_height_idx].v0 & 0xffffffff) ==
                        *(u32 *)&out_buf[i]) {

                  v0_input_to_state_type = CKTYPE_NORMAL32 | CK_IS_LEFT;
                  if (i + sizeof(u64) <= len &&
                      col[cmp_height_idx].v0 == *(u64 *)&out_buf[i]) {

                    v0_input_to_state_type = CKTYPE_NORMAL64 | CK_IS_LEFT;
                    maybe_add_auto(&out_buf[i], sizeof(u64));

                  } else

                    maybe_add_auto(&out_buf[i], sizeof(u32));

                }

              }

            }

            if (i + sizeof(u16) <= len &&
                SWAP16(col[cmp_height_idx].v0 & 0xffff) == *(u16 *)&out_buf[i])
              v0_input_to_state_type = CKTYPE_SWAP16 | CK_IS_LEFT;
            if (i + sizeof(u32) <= len &&
                SWAP32(col[cmp_height_idx].v0 & 0xffffffff) ==
                    *(u32 *)&out_buf[i]) {

              v0_input_to_state_type = CKTYPE_SWAP32 | CK_IS_LEFT;
              maybe_add_auto(&out_buf[i], sizeof(u32));

            }

            if (i + sizeof(u64) <= len &&
                SWAP64(col[cmp_height_idx].v0) == *(u64 *)&out_buf[i]) {

              v0_input_to_state_type = CKTYPE_SWAP64 | CK_IS_LEFT;
              maybe_add_auto(&out_buf[i], sizeof(u64));

            }

            v0_todo--;

          }

        }

        if (V1_HASDEP(deps_bitvec, i)) {

          ++v1_deps_counter;
          SET_BIT(v1_total_deps, i);

          if (v1_todo) {

            if ((col[cmp_height_idx].v1 & 0xff) == out_buf[i]) {

              v1_input_to_state_type = CKTYPE_NORMAL8 | CK_IS_RIGHT;
              if (i + sizeof(u16) <= len &&
                  (col[cmp_height_idx].v1 & 0xffff) == *(u16 *)&out_buf[i]) {

                v1_input_to_state_type = CKTYPE_NORMAL16 | CK_IS_RIGHT;
                if (i + sizeof(u32) <= len &&
                    (col[cmp_height_idx].v1 & 0xffffffff) ==
                        *(u32 *)&out_buf[i]) {

                  v1_input_to_state_type = CKTYPE_NORMAL32 | CK_IS_RIGHT;
                  if (i + sizeof(u64) <= len &&
                      col[cmp_height_idx].v1 == *(u64 *)&out_buf[i]) {

                    v1_input_to_state_type = CKTYPE_NORMAL64 | CK_IS_RIGHT;
                    maybe_add_auto(&out_buf[i], sizeof(u64));

                  } else

                    maybe_add_auto(&out_buf[i], sizeof(u32));

                }

              }

            }

            if (i + sizeof(u16) <= len &&
                SWAP16(col[cmp_height_idx].v1 & 0xffff) == *(u16 *)&out_buf[i])
              v1_input_to_state_type = CKTYPE_SWAP16 | CK_IS_RIGHT;
            if (i + sizeof(u32) <= len &&
                SWAP32(col[cmp_height_idx].v1 & 0xffffffff) ==
                    *(u32 *)&out_buf[i]) {

              v1_input_to_state_type = CKTYPE_SWAP32 | CK_IS_RIGHT;
              maybe_add_auto(&out_buf[i], sizeof(u32));

            }

            if (i + sizeof(u64) <= len &&
                SWAP64(col[cmp_height_idx].v1) == *(u64 *)&out_buf[i]) {

              v1_input_to_state_type = CKTYPE_SWAP64 | CK_IS_RIGHT;
              maybe_add_auto(&out_buf[i], sizeof(u64));

            }

            v1_todo--;

          }

        }

      }

      // must be always input-to-state
      if (v0_input_to_state_type) is_input_to_state |= IS_V0;
      if (v1_input_to_state_type) is_input_to_state |= IS_V1;

      if (checksums_info[cmp_cur_head.id] != CK_NOT_UNDER_CONTROL &&
          /*!is_checksum &&*/ cmp_cur_head.type == CMP_TYPE_INS) {

        if (checksums_info[cmp_cur_head.id]) {

          if ((checksums_info[cmp_cur_head.id] & CK_ARGTYPE_MASK) ==
              CK_IS_LEFT) {

            DBGPRINT("old v0 checksum!: %x (%lx %lx) %d    %d\n",
                     cmp_cur_head.id, col[cmp_height_idx].v0,
                     col[cmp_height_idx].v1, checksums_info[cmp_cur_head.id],
                     cmp_height_cnt);
            is_checksum            = IS_V0;
            ck_lens[ck_lens_idx++] = v1_deps_counter;

          } else {

            DBGPRINT("old v1 checksum!: %x (%lx %lx) %d    %d\n",
                     cmp_cur_head.id, col[cmp_height_idx].v0,
                     col[cmp_height_idx].v1, checksums_info[cmp_cur_head.id],
                     cmp_height_cnt);
            is_checksum            = IS_V1;
            ck_lens[ck_lens_idx++] = v0_deps_counter;

          }
          
          continue;

        }
        
      }
      
      if (skip_cmp_tries == 2) {

        /* This means that the skip is due to failed/total probability */
        continue;

      }

      if (cmp_cur_head.type == CMP_TYPE_RTN) {

        if (cmp_height_idx % 4 != 0)
          continue;

        for (i = 0; i < len; ++i) {

          stage_cur_byte = i;

          if (V0_HASDEP(deps_bitvec, i)) {

            /* Skip long try cmp data for cmp yet fuzzed */
            if (skip_cmp_tries || v0_deps_counter > 36)
              continue;
              
            if (i < len && !V0_HASDEP(deps_bitvec, i+1)) // new
              continue;

            stage_max = 32;
            if (len - i < 32) stage_max = len - i;

            stage_name  = "try rtn data";
            stage_short = "rtndata";

            stage_orig_hit_cnt = queued_paths + unique_crashes;

            char saved_buf[32];
            memcpy(saved_buf, &out_buf[i], stage_max);

            for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

              if (always_test_cmp_data ||
                  out_buf[i + stage_cur] ==
                      ((u8 *)&(col[cmp_height_idx + stage_cur / sizeof(u64)]
                                   .v0))[stage_cur % sizeof(u64)]) {

                out_buf[i + stage_cur] =
                    ((u8 *)&(col[cmp_height_idx + stage_cur / sizeof(u64)]
                                 .v1))[stage_cur % sizeof(u64)];

                
                if (stage_cur >= (v0_deps_counter -8)) // guess a bit the len
                  if (weizz_perform_fuzz(i, stage_cur, out_buf, len))
                    goto exit_weizz_fuzz_one;
                
                //if (stage_orig_hit_cnt != queued_paths + unique_crashes)
                //  break;

              } else

                break;

            }

            memcpy(&out_buf[i], saved_buf, stage_max);

            stage_new_hit_cnt = queued_paths + unique_crashes;

            stage_finds[STAGE_RTNDATA] +=
                stage_new_hit_cnt - stage_orig_hit_cnt;
            stage_cycles[STAGE_RTNDATA] += stage_max;

            if (stage_new_hit_cnt - stage_orig_hit_cnt) skip_cmp_tries = 1;

            // break;

          } else if (V1_HASDEP(deps_bitvec, i)) {

            /* Skip long try cmp data for cmp yet fuzzed */
            if (skip_cmp_tries || v1_deps_counter > 36)
              continue;
              
            if (i < len && !V1_HASDEP(deps_bitvec, i+1)) // new
              continue;

            stage_max = 32;
            if (len - i < 32) stage_max = len - i;

            stage_name  = "try rtn data";
            stage_short = "rtndata";

            stage_orig_hit_cnt = queued_paths + unique_crashes;

            char saved_buf[32];
            memcpy(saved_buf, &out_buf[i], stage_max);

            for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

              if (always_test_cmp_data ||
                  out_buf[i + stage_cur] ==
                      ((u8 *)&(col[cmp_height_idx + stage_cur / sizeof(u64)]
                                   .v1))[stage_cur % sizeof(u64)]) {

                out_buf[i + stage_cur] =
                    ((u8 *)&(col[cmp_height_idx + stage_cur / sizeof(u64)]
                                 .v0))[stage_cur % sizeof(u64)];

                if (stage_cur >= (v1_deps_counter -8)) // guess a bit the len
                  if (weizz_perform_fuzz(i, stage_cur, out_buf, len))
                    goto exit_weizz_fuzz_one;
                
                //if (stage_orig_hit_cnt != queued_paths + unique_crashes)
                //  break;

              } else

                break;

            }

            memcpy(&out_buf[i], saved_buf, stage_max);

            stage_new_hit_cnt = queued_paths + unique_crashes;

            stage_finds[STAGE_RTNDATA] +=
                stage_new_hit_cnt - stage_orig_hit_cnt;
            stage_cycles[STAGE_RTNDATA] += stage_max;

            if (stage_new_hit_cnt - stage_orig_hit_cnt) skip_cmp_tries = 1;

            // break;

          }

        }

        stage_cur_byte = -1;

        continue;

      }

      if (!always_test_cmp_data &&
          col[cmp_height_idx].v0 == col[cmp_height_idx].v1)
        continue;

      if (cmp_height_idx != cmp_height_cnt - 1 &&
          col[cmp_height_idx].v0 == col[cmp_height_idx + 1].v0 &&
          col[cmp_height_idx].v1 == col[cmp_height_idx + 1].v1) {

        continue;

      }

      for (i = 0; i < len; ++i) {

        stage_cur_byte = i;

        if (V0_HASDEP(deps_bitvec, i)) {

          /* Skip long try cmp data for cmp already fuzzed */
          if (skip_cmp_tries == 3 || (always_test_cmp_data && skip_cmp_tries) || v0_deps_counter > 12)
            continue;

          // u8 must_skip_next_execs = 0;

          saved_brute = out_buf[i];

          /****************
           * TRY CMP DATA *
           ****************/

          stage_name  = "try cmp data";
          stage_short = "cmpdata";
          stage_cur   = 0;

          /* Replace with cmp data as byte, word, dword, or qword.
             Use also cmp data +/- 1. */

          stage_orig_hit_cnt = queued_paths + unique_crashes;

          stage_max = 42;

          /* One byte */

          if (always_test_cmp_data ||
              out_buf[i] == (col[cmp_height_idx].v0 & 0xff)) {

            out_buf[i] = col[cmp_height_idx].v1 & 0xff;

            if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
              goto exit_weizz_fuzz_one;

            if (queued_paths + unique_crashes != stage_orig_hit_cnt)
              goto v0_restore_saved;

            stage_cur++;
            out_buf[i] += 1;

            if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
              goto exit_weizz_fuzz_one;

            if (queued_paths + unique_crashes != stage_orig_hit_cnt)
              goto v0_restore_saved;

            stage_cur++;
            out_buf[i] -= 2;

            if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
              goto exit_weizz_fuzz_one;

            if (queued_paths + unique_crashes != stage_orig_hit_cnt)
              goto v0_restore_saved;

          }

          if (i + 1 < len) {

            u16 saved_brute_1 = *(u16 *)&out_buf[i];

            if (always_test_cmp_data ||
                *(u16 *)&out_buf[i] == (col[cmp_height_idx].v0 & 0xffff)) {

              stage_cur++;
              *(u16 *)&out_buf[i] = col[cmp_height_idx].v1 & 0xffff;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] += 1;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] -= 2;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

            }

            if ((s16)col[cmp_height_idx].v1 !=
                    (s16)(u8)col[cmp_height_idx].v1 &&
                (always_test_cmp_data ||
                 *(u16 *)&out_buf[i] == (col[cmp_height_idx].v0 & 0xffff))) {

              stage_cur++;
              *(u16 *)&out_buf[i] = (s16)(u8)col[cmp_height_idx].v1;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] += 1;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] -= 2;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

            }

            if (always_test_cmp_data ||
                *(u16 *)&out_buf[i] ==
                    SWAP16(col[cmp_height_idx].v0 & 0xffff)) {

              stage_val_type = STAGE_VAL_BE;

              stage_cur++;
              *(u16 *)&out_buf[i] = SWAP16(col[cmp_height_idx].v1 & 0xffff);

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] += 1;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] -= 2;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v0_restore_saved_1;

              stage_val_type = STAGE_VAL_NONE;

            }

            if (i + 3 < len) {

              u32 saved_brute_2 = *(u32 *)&out_buf[i];

              if (always_test_cmp_data ||
                  *(u32 *)&out_buf[i] ==
                      (col[cmp_height_idx].v0 & 0xffffffff)) {

                stage_cur++;
                *(u32 *)&out_buf[i] = col[cmp_height_idx].v1 & 0xffffffff;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

              }

              if ((s32)col[cmp_height_idx].v1 !=
                      (s32)(u8)col[cmp_height_idx].v1 &&
                  (always_test_cmp_data ||
                   *(u32 *)&out_buf[i] ==
                       (col[cmp_height_idx].v0 & 0xffffffff))) {

                stage_cur++;
                *(u16 *)&out_buf[i] = (s32)(u8)col[cmp_height_idx].v1;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

              }

              if ((s32)col[cmp_height_idx].v1 !=
                      (s32)(u16)col[cmp_height_idx].v1 &&
                  (always_test_cmp_data ||
                   *(u32 *)&out_buf[i] ==
                       (col[cmp_height_idx].v0 & 0xffffffff))) {

                stage_cur++;
                *(u16 *)&out_buf[i] = (s32)(u16)col[cmp_height_idx].v1;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

              }

              if (always_test_cmp_data ||
                  *(u32 *)&out_buf[i] ==
                      SWAP32(col[cmp_height_idx].v0 & 0xffffffff)) {

                stage_val_type = STAGE_VAL_BE;

                stage_cur++;
                *(u32 *)&out_buf[i] =
                    SWAP32(col[cmp_height_idx].v1 & 0xffffffff);

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v0_restore_saved_2;

                stage_val_type = STAGE_VAL_NONE;

              }

              if (i + 7 < len) {

                u64 saved_brute_3 = *(u64 *)&out_buf[i];

                if (always_test_cmp_data ||
                    *(u64 *)&out_buf[i] == col[cmp_height_idx].v0) {

                  stage_cur++;
                  *(u64 *)&out_buf[i] = col[cmp_height_idx].v1;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                }

                if ((s64)col[cmp_height_idx].v1 !=
                        (s64)(u8)col[cmp_height_idx].v1 &&
                    (always_test_cmp_data ||
                     *(u64 *)&out_buf[i] == col[cmp_height_idx].v0)) {

                  stage_cur++;
                  *(u16 *)&out_buf[i] = (s64)(u8)col[cmp_height_idx].v1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                }

                if ((s64)col[cmp_height_idx].v1 !=
                        (s64)(u16)col[cmp_height_idx].v1 &&
                    (always_test_cmp_data ||
                     *(u64 *)&out_buf[i] == col[cmp_height_idx].v0)) {

                  stage_cur++;
                  *(u16 *)&out_buf[i] = (s64)(u16)col[cmp_height_idx].v1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                }

                if ((s64)col[cmp_height_idx].v1 !=
                        (s64)(u32)col[cmp_height_idx].v1 &&
                    (always_test_cmp_data ||
                     *(u64 *)&out_buf[i] == col[cmp_height_idx].v0)) {

                  stage_cur++;
                  *(u16 *)&out_buf[i] = (s64)(u32)col[cmp_height_idx].v1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                }

                if (always_test_cmp_data ||
                    *(u64 *)&out_buf[i] == SWAP64(col[cmp_height_idx].v0)) {

                  stage_val_type = STAGE_VAL_BE;

                  stage_cur++;
                  *(u64 *)&out_buf[i] = SWAP64(col[cmp_height_idx].v1);

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v0_restore_saved_3;

                  stage_val_type = STAGE_VAL_NONE;

                }

v0_restore_saved_3:
                *(u64 *)&out_buf[i] = saved_brute_3;

              }

v0_restore_saved_2:
              *(u32 *)&out_buf[i] = saved_brute_2;

            }

v0_restore_saved_1:
            *(u16 *)&out_buf[i] = saved_brute_1;

          }

v0_restore_saved:
          stage_cur++;
          out_buf[i] = saved_brute;

          stage_val_type = STAGE_VAL_NONE;

          // if (must_skip_next_execs) goto v0_cmp_stage_end;

          /* To ASCII */

          /* char   stringified[32];
          size_t slen = u64_to_str(stringified, col[cmp_height_idx].v1);
          if (i + slen < len) {

            char saved_buf[32];
            memcpy(saved_buf, &out_buf[i], slen);

            memcpy(&out_buf[i], stringified, slen);

            if (weizz_perform_fuzz(i, slen, out_buf, len))
              goto exit_weizz_fuzz_one;

            memcpy(&out_buf[i], saved_buf, slen);
            stage_cur++;

          } */

          /* From ASCII */
          /* char ascii_buf[12];

          memcpy(ascii_buf, &col[cmp_height_idx].v1, sizeof(u64));
          ascii_buf[sizeof(u64)] = 0;
          slen                   = strlen(ascii_buf);

          if (i + slen < len) {

            char saved_buf[32];
            memcpy(saved_buf, &out_buf[i], slen);

            memcpy(&out_buf[i], ascii_buf, slen);

            if (weizz_perform_fuzz(i, slen, out_buf, len))
              goto exit_weizz_fuzz_one;

            memcpy(&out_buf[i], saved_buf, slen);
            stage_cur++;

          } 

          u64 decoded = atoll(ascii_buf);

          if (i + sizeof(u32) < len) {

            u32 saved_num = *(u32 *)&out_buf[i];

            *(u32 *)&out_buf[i] = (u32)decoded;

            if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
              goto exit_weizz_fuzz_one;

            *(u32 *)&out_buf[i] = saved_num;
            stage_cur++;

          }

          if (i + sizeof(u64) < len) {

            u64 saved_num = *(u64 *)&out_buf[i];

            *(u64 *)&out_buf[i] = (u64)decoded;

            if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
              goto exit_weizz_fuzz_one;

            *(u64 *)&out_buf[i] = saved_num;
            stage_cur++;

          } */

// v0_cmp_stage_end:

          stage_new_hit_cnt = queued_paths + unique_crashes;

          stage_finds[STAGE_CMPDATA] += stage_new_hit_cnt - stage_orig_hit_cnt;
          stage_cycles[STAGE_CMPDATA] += stage_cur;

          if (stage_new_hit_cnt - stage_orig_hit_cnt) skip_cmp_tries = 1;

          if (enable_byte_brute && unlikely(!GET_BIT(already_bruted_bits, i))) {

            /*******************
             * BYTE BRUTEFORCE *
             *******************/

            ++weizz_brute_num;

            stage_name  = "byte bruteforce";
            stage_short = "brute";
            stage_cur   = 0;
            stage_max   = 255;

            stage_orig_hit_cnt = queued_paths + unique_crashes;

            for (j = 0; j < 256; ++j) {

              stage_cur = j;
              if (unlikely(j == (col[cmp_height_idx].v0 & 0xff)) ||
                  unlikely(j == (col[cmp_height_idx].v1 & 0xff)))
                continue;

              out_buf[i] = (u8)j;

              if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
                goto exit_weizz_fuzz_one;

            }

            out_buf[i] = saved_brute;

            SET_BIT(already_bruted_bits, i);

            stage_new_hit_cnt = queued_paths + unique_crashes;

            stage_finds[STAGE_BRUTE] += stage_new_hit_cnt - stage_orig_hit_cnt;
            stage_cycles[STAGE_BRUTE] += stage_max;

          }

        }

        if (V1_HASDEP(deps_bitvec, i)) {

          /* Skip long try cmp data for cmp yet fuzzed */
          if (skip_cmp_tries == 3 || (always_test_cmp_data && skip_cmp_tries) || v1_deps_counter > 12)
            continue;

          // u8 must_skip_next_execs = 0;

          saved_brute = out_buf[i];

          /****************
           * TRY CMP DATA *
           ****************/

          stage_name  = "try cmp data";
          stage_short = "cmpdata";
          stage_cur   = 0;

          /* Replace with cmp data as byte, word, dword, or qword.
             Use also cmp data +/- 1. */

          stage_orig_hit_cnt = queued_paths + unique_crashes;

          stage_max = 42;

          /* One byte */

          if (always_test_cmp_data ||
              out_buf[i] == (col[cmp_height_idx].v1 & 0xff)) {

            out_buf[i] = col[cmp_height_idx].v0 & 0xff;

            if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
              goto exit_weizz_fuzz_one;

            if (queued_paths + unique_crashes != stage_orig_hit_cnt)
              goto v1_restore_saved;

            stage_cur++;

            out_buf[i] += 1;

            if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
              goto exit_weizz_fuzz_one;

            if (queued_paths + unique_crashes != stage_orig_hit_cnt)
              goto v1_restore_saved;

            stage_cur++;
            out_buf[i] -= 2;

            if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
              goto exit_weizz_fuzz_one;

            if (queued_paths + unique_crashes != stage_orig_hit_cnt)
              goto v1_restore_saved;

          }

          if (i + 1 < len) {

            u16 saved_brute_1 = *(u16 *)&out_buf[i];

            if (always_test_cmp_data ||
                *(u16 *)&out_buf[i] == (col[cmp_height_idx].v1 & 0xffff)) {

              stage_cur++;
              *(u16 *)&out_buf[i] = col[cmp_height_idx].v0 & 0xffff;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] += 1;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] -= 2;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

            }

            if ((s16)col[cmp_height_idx].v0 !=
                    (s16)(u8)col[cmp_height_idx].v0 &&
                (always_test_cmp_data ||
                 *(u16 *)&out_buf[i] == (col[cmp_height_idx].v1 & 0xffff))) {

              stage_cur++;
              *(u16 *)&out_buf[i] = (s16)(u8)col[cmp_height_idx].v0;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] += 1;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] -= 2;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

            }

            if (always_test_cmp_data ||
                *(u16 *)&out_buf[i] ==
                    SWAP16(col[cmp_height_idx].v1 & 0xffff)) {

              stage_val_type = STAGE_VAL_BE;

              stage_cur++;
              *(u16 *)&out_buf[i] = SWAP16(col[cmp_height_idx].v0 & 0xffff);

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] += 1;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

              stage_cur++;
              *(u16 *)&out_buf[i] -= 2;

              if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                goto exit_weizz_fuzz_one;

              if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                goto v1_restore_saved_1;

              stage_val_type = STAGE_VAL_NONE;

            }

            if (i + 3 < len) {

              u32 saved_brute_2 = *(u32 *)&out_buf[i];

              if (always_test_cmp_data ||
                  *(u32 *)&out_buf[i] ==
                      (col[cmp_height_idx].v1 & 0xffffffff)) {

                stage_cur++;
                *(u32 *)&out_buf[i] = (col[cmp_height_idx].v0 & 0xffffffff);

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

              }

              if ((s32)col[cmp_height_idx].v0 !=
                      (s32)(u8)col[cmp_height_idx].v0 &&
                  (always_test_cmp_data ||
                   *(u32 *)&out_buf[i] ==
                       (col[cmp_height_idx].v1 & 0xffffffff))) {

                stage_cur++;
                *(u16 *)&out_buf[i] = (s32)(u8)col[cmp_height_idx].v0;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

              }

              if ((s32)col[cmp_height_idx].v0 !=
                      (s32)(u16)col[cmp_height_idx].v0 &&
                  (always_test_cmp_data ||
                   *(u32 *)&out_buf[i] ==
                       (col[cmp_height_idx].v1 & 0xffffffff))) {

                stage_cur++;
                *(u16 *)&out_buf[i] = (s32)(u16)col[cmp_height_idx].v0;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u16 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

              }

              if (always_test_cmp_data ||
                  *(u32 *)&out_buf[i] ==
                      SWAP32(col[cmp_height_idx].v1 & 0xffffffff)) {

                stage_val_type = STAGE_VAL_BE;

                stage_cur++;
                *(u32 *)&out_buf[i] =
                    SWAP32(col[cmp_height_idx].v0 & 0xffffffff);

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] += 1;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_cur++;
                *(u32 *)&out_buf[i] -= 2;

                if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
                  goto exit_weizz_fuzz_one;

                if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                  goto v1_restore_saved_2;

                stage_val_type = STAGE_VAL_NONE;

              }

              if (i + 7 < len) {

                u64 saved_brute_3 = *(u64 *)&out_buf[i];

                if (always_test_cmp_data ||
                    *(u64 *)&out_buf[i] == col[cmp_height_idx].v1) {

                  stage_cur++;
                  *(u64 *)&out_buf[i] = col[cmp_height_idx].v0;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                }

                if ((s64)col[cmp_height_idx].v0 !=
                        (s64)(u8)col[cmp_height_idx].v0 &&
                    (always_test_cmp_data ||
                     *(u64 *)&out_buf[i] == col[cmp_height_idx].v1)) {

                  stage_cur++;
                  *(u16 *)&out_buf[i] = (s64)(u8)col[cmp_height_idx].v0;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                }

                if ((s64)col[cmp_height_idx].v0 !=
                        (s64)(u16)col[cmp_height_idx].v0 &&
                    (always_test_cmp_data ||
                     *(u64 *)&out_buf[i] == col[cmp_height_idx].v1)) {

                  stage_cur++;
                  *(u16 *)&out_buf[i] = (s64)(u16)col[cmp_height_idx].v0;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                }

                if ((s64)col[cmp_height_idx].v0 !=
                        (s64)(u32)col[cmp_height_idx].v0 &&
                    (always_test_cmp_data ||
                     *(u64 *)&out_buf[i] == col[cmp_height_idx].v1)) {

                  stage_cur++;
                  *(u16 *)&out_buf[i] = (s64)(u32)col[cmp_height_idx].v0;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u16 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u16), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                }

                if (always_test_cmp_data ||
                    *(u64 *)&out_buf[i] == SWAP64(col[cmp_height_idx].v1)) {

                  stage_val_type = STAGE_VAL_BE;

                  stage_cur++;
                  *(u64 *)&out_buf[i] = SWAP64(col[cmp_height_idx].v0);

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] += 1;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_cur++;
                  *(u64 *)&out_buf[i] -= 2;

                  if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
                    goto exit_weizz_fuzz_one;

                  if (queued_paths + unique_crashes != stage_orig_hit_cnt)
                    goto v1_restore_saved_3;

                  stage_val_type = STAGE_VAL_NONE;

                }

v1_restore_saved_3:
                *(u64 *)&out_buf[i] = saved_brute_3;

              }

v1_restore_saved_2:
              *(u32 *)&out_buf[i] = saved_brute_2;

            }

v1_restore_saved_1:
            *(u16 *)&out_buf[i] = saved_brute_1;

          }

v1_restore_saved:
          stage_cur++;
          out_buf[i] = saved_brute;

          stage_val_type = STAGE_VAL_NONE;

          // if (must_skip_next_execs) goto v1_cmp_stage_end;

          /* To ASCII */

          /* char   stringified[32];
          size_t slen = u64_to_str(stringified, col[cmp_height_idx].v0);
          if (i + slen < len) {

            char saved_buf[32];
            memcpy(saved_buf, &out_buf[i], slen);

            memcpy(&out_buf[i], stringified, slen);

            if (weizz_perform_fuzz(i, slen, out_buf, len))
              goto exit_weizz_fuzz_one;

            memcpy(&out_buf[i], saved_buf, slen);
            stage_cur++;

          } */

          /* From ASCII */
          /* char ascii_buf[12];

          memcpy(ascii_buf, &col[cmp_height_idx].v0, sizeof(u64));
          ascii_buf[sizeof(u64)] = 0;
          slen                   = strlen(ascii_buf);

          if (i + slen < len) {

            char saved_buf[32];
            memcpy(saved_buf, &out_buf[i], slen);

            memcpy(&out_buf[i], ascii_buf, slen);

            if (weizz_perform_fuzz(i, slen, out_buf, len))
              goto exit_weizz_fuzz_one;

            memcpy(&out_buf[i], saved_buf, slen);
            stage_cur++;

          }

          u64 decoded = atoll(ascii_buf);

          if (i + sizeof(u32) < len) {

            u32 saved_num = *(u32 *)&out_buf[i];

            *(u32 *)&out_buf[i] = (u32)decoded;

            if (weizz_perform_fuzz(i, sizeof(u32), out_buf, len))
              goto exit_weizz_fuzz_one;

            *(u32 *)&out_buf[i] = saved_num;
            stage_cur++;

          }

          if (i + sizeof(u64) < len) {

            u64 saved_num = *(u64 *)&out_buf[i];

            *(u64 *)&out_buf[i] = (u64)decoded;

            if (weizz_perform_fuzz(i, sizeof(u64), out_buf, len))
              goto exit_weizz_fuzz_one;

            *(u64 *)&out_buf[i] = saved_num;
            stage_cur++;

          } */

// v1_cmp_stage_end:

          stage_new_hit_cnt = queued_paths + unique_crashes;

          stage_finds[STAGE_CMPDATA] += stage_new_hit_cnt - stage_orig_hit_cnt;
          stage_cycles[STAGE_CMPDATA] += stage_cur;

          if (stage_new_hit_cnt - stage_orig_hit_cnt) skip_cmp_tries = 1;

          // TODO remove code duplicates

          if (enable_byte_brute && unlikely(!GET_BIT(already_bruted_bits, i))) {

            /*******************
             * BYTE BRUTEFORCE *
             *******************/

            ++weizz_brute_num;

            stage_name  = "byte bruteforce";
            stage_short = "brute";
            stage_cur   = 0;
            stage_max   = 255;

            stage_orig_hit_cnt = queued_paths + unique_crashes;

            for (j = 0; j < 256; ++j) {

              stage_cur = j;
              if (unlikely(j == (col[cmp_height_idx].v0 & 0xff)) ||
                  unlikely(j == (col[cmp_height_idx].v1 & 0xff)))
                continue;

              out_buf[i] = (u8)j;

              if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
                goto exit_weizz_fuzz_one;

            }

            out_buf[i] = saved_brute;

            SET_BIT(already_bruted_bits, i);

            stage_new_hit_cnt = queued_paths + unique_crashes;

            stage_finds[STAGE_BRUTE] += stage_new_hit_cnt - stage_orig_hit_cnt;
            stage_cycles[STAGE_BRUTE] += stage_max;

          }

        }

      }

    }

  }

  stage_cur_byte = -1;

  for (cmp_height_idx = cmp_height_cnt - 1; cmp_height_idx >= 0;
       --cmp_height_idx) {

    if (DEPS_EXISTS(cmp_cur, cmp_height_idx)) {
    
      u8 *deps_bitvec                   = DEPS_GET(cmp_cur, cmp_height_idx);
      DEPS_GET(cmp_cur, cmp_height_idx) = NULL;
        
      /*fprintf(stderr, ">>>>>> (%d, %x) %x %d\n", is_checksum, checksums_info[cmp_cur_head.id], cmp_cur, cmp_cur_head.cnt);
      fprintf(stderr, "V0: ");
      for (i = 0; i < len; ++i) fprintf(stderr, ANY_V0_HASDEP(deps_bitvec, i) ? "1":"0");
      fprintf(stderr, "\nV1: ");
      for (i = 0; i < len; ++i) fprintf(stderr, ANY_V1_HASDEP(deps_bitvec, i) ? "1":"0");
      fprintf(stderr, "\n");*/
        
      if(place_tags(len, deps_bitvec, tags, is_checksum, is_input_to_state, checksum_coverage)) {
        has_placed_tag = 1;
      }
        
      ck_free(deps_bitvec);
      
    }
  
  }

  if (is_checksum) cmp_patch_local_map[cmp_cur_head.id] = 0xff;

  if (has_placed_tag) {

    last_cmp_that_placed_tag = cmp_cur_head.id;

  }

  /* This is an aggressive assumption */
  if (weizz_fuzz_found) {

    ret = 0;
    goto exit_weizz_fuzz_one;

  }

  /****************
   * LOCKED HAVOC *
   ****************/

  u32 locked_bytes = 0, v0_locked_bytes = 0, v1_locked_bytes = 0;
  u32 last_locked_idx = 0;

  for (i = 0; i < len; ++i) {

    if (GET_BIT(v0_total_deps, i)) {

      ++v0_locked_bytes;
      ++locked_bytes;
      last_locked_idx = i;

      if (GET_BIT(v1_total_deps, i)) { ++v1_locked_bytes; }

    } else if (!GET_BIT(v1_total_deps, i))

      continue;
    else {

      ++v1_locked_bytes;
      ++locked_bytes;
      last_locked_idx = i;

    }

  }

  if (skip_cmp_tries || !locked_bytes) {

    ret = 0;
    goto exit_weizz_fuzz_one;

  }

  if (!enable_byte_brute && locked_bytes == 1) {

    i = last_locked_idx;
    if (GET_BIT(already_bruted_bits, i)) {

      ret = 0;
      goto exit_weizz_fuzz_one;

    }

    ++weizz_brute_num;

    saved_brute     = out_buf[i];

    stage_name  = "byte bruteforce";
    stage_short = "brute";
    stage_cur   = 0;
    stage_max   = 255;

    stage_orig_hit_cnt = queued_paths + unique_crashes;

    for (j = 0; j < 256; ++j) {

      out_buf[i] = (u8)j;

      if (weizz_perform_fuzz(i, sizeof(u8), out_buf, len))
        goto exit_weizz_fuzz_one;

    }

    out_buf[i] = saved_brute;

    SET_BIT(already_bruted_bits, i);

    stage_new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_BRUTE] += stage_new_hit_cnt - stage_orig_hit_cnt;
    stage_cycles[STAGE_BRUTE] += stage_max;

    ret = 0;
    goto exit_weizz_fuzz_one;

  }

  /* Avoid large havoc on already fuzzed inputs */
  if (!enable_locked_havoc ||
      (pass_stats[cmp_cur].total &&
      pass_stats[cmp_cur].total != pass_stats[cmp_cur].failed)) {

    ret = 0;
    goto exit_weizz_fuzz_one;

  }

  j = 0;

  if (v0_locked_bytes <= 8 && v1_locked_bytes <= 8) {

    mutables_idx_map = ck_alloc_nozero(locked_bytes * sizeof(u32));

    for (i = 0; i < len; ++i) {

      if (GET_BIT(v0_total_deps, i))
        mutables_idx_map[j++] = i;
      else if (GET_BIT(v1_total_deps, i))
        mutables_idx_map[j++] = i;

    }

  } else if (v0_locked_bytes > 8 && v1_locked_bytes <= 8 && v1_locked_bytes) {

    locked_bytes     = v1_locked_bytes;
    mutables_idx_map = ck_alloc_nozero(locked_bytes * sizeof(u32));

    for (i = 0; i < len; ++i) {

      if (GET_BIT(v1_total_deps, i)) mutables_idx_map[j++] = i;

    }

  } else if (v0_locked_bytes <= 8 && v1_locked_bytes > 8 && v0_locked_bytes) {

    locked_bytes     = v0_locked_bytes;
    mutables_idx_map = ck_alloc_nozero(locked_bytes * sizeof(u32));

    for (i = 0; i < len; ++i) {

      if (GET_BIT(v0_total_deps, i)) mutables_idx_map[j++] = i;

    }

  } else {

    ret = 0;
    goto exit_weizz_fuzz_one;

  }

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  stage_name  = "locked havoc";
  stage_short = "locked";
  stage_max   = HAVOC_CYCLES * perf_score / havoc_div /
              20;  // / 100 not needed, many will be skipped

  saved_buf = out_buf;
  out_buf   = ck_alloc_nozero(len);
  memcpy(out_buf, saved_buf, len);

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  prev_queued        = queued_paths;
  orig_hit_cnt       = queued_paths + unique_crashes;
  stage_orig_hit_cnt = orig_hit_cnt;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;

    for (i = 0; i < use_stacking; i++) {

      switch (UR(13 + ((extras_cnt + a_extras_cnt) ? 1 : 0))) {

        case 0: {

          /* Flip a single bit somewhere. Spooky! */

          s32 bit_idx = (mutables_idx_map[UR(locked_bytes)] << 3) + UR(8);

          FLIP_BIT(out_buf, bit_idx);

          break;

        }

        case 1: {

          /* Set byte to interesting value. */

          u8 val;

          switch (UR(3)) {

            case 0: val = col[1 + UR(cmp_height_cnt)].v0; break;
            case 1: val = col[1 + UR(cmp_height_cnt)].v1; break;
            default: val = interesting_8[UR(sizeof(interesting_8))]; break;

          }

          s32 byte_idx      = mutables_idx_map[UR(locked_bytes)];
          out_buf[byte_idx] = val;

          break;

        }

        case 2: {

          /* Set word to interesting value, randomly choosing endian. */

          if (len < 2) break;

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx >= len - 1) break;

          switch (UR(6)) {

            case 0:
              *(u16 *)(out_buf + byte_idx) = col[1 + UR(cmp_height_cnt)].v0;
              break;
            case 1:
              *(u16 *)(out_buf + byte_idx) = col[1 + UR(cmp_height_cnt)].v1;
              break;
            case 2:
              *(u16 *)(out_buf + byte_idx) =
                  SWAP16(col[1 + UR(cmp_height_cnt)].v0);
              break;
            case 3:
              *(u16 *)(out_buf + byte_idx) =
                  SWAP16(col[1 + UR(cmp_height_cnt)].v1);
              break;
            case 4:
              *(u16 *)(out_buf + byte_idx) =
                  interesting_16[UR(sizeof(interesting_16) >> 1)];
              break;
            case 5:
              *(u16 *)(out_buf + byte_idx) =
                  SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);
              break;

          }

          break;

        }

        case 3: {

          /* Set dword to interesting value, randomly choosing endian. */

          if (len < 4) break;

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx >= len - 3) break;

          switch (UR(6)) {

            case 0:
              *(u32 *)(out_buf + byte_idx) = col[1 + UR(cmp_height_cnt)].v0;
              break;
            case 1:
              *(u32 *)(out_buf + byte_idx) = col[1 + UR(cmp_height_cnt)].v1;
              break;
            case 2:
              *(u32 *)(out_buf + byte_idx) =
                  SWAP32(col[1 + UR(cmp_height_cnt)].v0);
              break;
            case 3:
              *(u32 *)(out_buf + byte_idx) =
                  SWAP32(col[1 + UR(cmp_height_cnt)].v1);
              break;
            case 4:
              *(u32 *)(out_buf + byte_idx) =
                  interesting_32[UR(sizeof(interesting_32) >> 2)];
              break;
            case 5:
              *(u32 *)(out_buf + byte_idx) =
                  SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);
              break;

          }

          break;

        }

        case 4: {

          /* Set qword to interesting value, randomly choosing endian. */

          if (len < 8) break;

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx >= len - 7) break;

          switch (UR(6)) {

            case 0:
              *(u64 *)(out_buf + byte_idx) = col[1 + UR(cmp_height_cnt)].v0;
              break;
            case 1:
              *(u64 *)(out_buf + byte_idx) = col[1 + UR(cmp_height_cnt)].v1;
              break;
            case 2:
              *(u64 *)(out_buf + byte_idx) =
                  SWAP32(col[1 + UR(cmp_height_cnt)].v0);
              break;
            case 3:
              *(u64 *)(out_buf + byte_idx) =
                  SWAP32(col[1 + UR(cmp_height_cnt)].v1);
              break;
            case 4:
              *(u64 *)(out_buf + byte_idx) =
                  (s64)interesting_32[UR(sizeof(interesting_32) >> 2)];
              break;
            case 5:
              *(u64 *)(out_buf + byte_idx) =
                  SWAP64((s64)interesting_32[UR(sizeof(interesting_32) >> 2)]);
              break;

          }

          break;

        }

        case 5: {

          /* Randomly subtract from byte. */

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];
          out_buf[byte_idx] -= 1 + UR(ARITH_MAX);

          break;

        }

        case 6: {

          /* Randomly add to byte. */

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];
          out_buf[byte_idx] += 1 + UR(ARITH_MAX);

          break;

        }

        case 7: {

          /* Randomly subtract from word, random endian. */

          if (len < 2) break;

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx >= len - 1) break;

          if (UR(2)) {

            *(u16 *)(out_buf + byte_idx) -= 1 + UR(ARITH_MAX);

          } else {

            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(out_buf + byte_idx) =
                SWAP16(SWAP16(*(u16 *)(out_buf + byte_idx)) - num);

          }

          break;

        }

        case 8: {

          /* Randomly add to word, random endian. */

          if (len < 2) break;

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx >= len - 1) break;

          if (UR(2)) {

            *(u16 *)(out_buf + byte_idx) += 1 + UR(ARITH_MAX);

          } else {

            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(out_buf + byte_idx) =
                SWAP16(SWAP16(*(u16 *)(out_buf + byte_idx)) + num);

          }

          break;

        }

        case 9: {

          /* Randomly subtract from dword, random endian. */

          if (len < 4) break;

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx >= len - 3) break;

          if (UR(2)) {

            *(u32 *)(out_buf + byte_idx) -= 1 + UR(ARITH_MAX);

          } else {

            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(out_buf + byte_idx) =
                SWAP32(SWAP32(*(u32 *)(out_buf + byte_idx)) - num);

          }

          break;

        }

        case 10: {

          /* Randomly add to dword, random endian. */

          if (len < 4) break;

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx >= len - 3) break;

          if (UR(2)) {

            *(u32 *)(out_buf + byte_idx) += 1 + UR(ARITH_MAX);

          } else {

            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(out_buf + byte_idx) =
                SWAP32(SWAP32(*(u32 *)(out_buf + byte_idx)) + num);

          }

          break;

        }

        case 11: {

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];
          out_buf[byte_idx] ^= 1 + UR(255);

          break;

        }

        case 12: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          u32 copy_from, copy_to, copy_len;

          if (len < 2) break;

          copy_len = choose_block_len(len - 1);

          copy_from = UR(len - copy_len + 1);

          s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

          if (byte_idx + copy_len >= len) break;

          copy_to = byte_idx;

          if (UR(4)) {

            if (copy_from != copy_to)
              memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          } else

            memset(out_buf + copy_to, UR(2) ? UR(256) : out_buf[UR(len)],
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

            s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

            if (byte_idx + extra_len >= len) break;

            insert_at = byte_idx;
            memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {

            /* No auto extras or odds in our favor. Use the dictionary. */

            u32 use_extra = UR(extras_cnt);
            u32 extra_len = extras[use_extra].len;
            u32 insert_at;

            if (extra_len > len) break;

            s32 byte_idx = mutables_idx_map[UR(locked_bytes)];

            if (byte_idx + extra_len >= len) break;

            insert_at = byte_idx;
            memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

          }

          break;

        }

      }

    }

    if (unlikely(common_light_fuzz_stuff(out_buf, len))) goto exit_locked_havoc;

    new_hit_cnt = queued_paths + unique_crashes;

    if (unlikely(new_hit_cnt != orig_hit_cnt)) {

      weizz_fuzz_found = 1;

      if (queued_paths != prev_queued) {

        if (surgical_use_derived_tags) {

          queue_top->use_derived_tags = 1;
          queue_top->tags_fname      = queue_cur->tags_fname;
          queue_top->parent          = queue_cur;

          add_to_tg_queue(queue_top);

        }

      }

      /* Exit locked havoc loop */
      break;

    }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    memcpy(out_buf, saved_buf, len);

  }

  ret = 0;

  stage_new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_LOCKED_HAVOC] += stage_new_hit_cnt - stage_orig_hit_cnt;
  stage_cycles[STAGE_LOCKED_HAVOC] += stage_cur + 1;

exit_locked_havoc:

  ck_free(mutables_idx_map);
  ck_free(out_buf);

exit_weizz_fuzz_one:

  if (ret) {
  
    for (cmp_height_idx = cmp_height_cnt - 1; cmp_height_idx >= 0;
       --cmp_height_idx) {

      if (DEPS_EXISTS(cmp_cur, cmp_height_idx)) {
      
        u8 *deps_bitvec                   = DEPS_GET(cmp_cur, cmp_height_idx);
        DEPS_GET(cmp_cur, cmp_height_idx) = NULL;

        ck_free(deps_bitvec);
        
      }
    
    }
  
  }

  ck_free(v0_total_deps);
  ck_free(v1_total_deps);

  return ret;

}

