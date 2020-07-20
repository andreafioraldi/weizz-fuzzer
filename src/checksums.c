/*
   weizz - checksums patching and fixing related routines
   ------------------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "weizz.h"

void read_patch_map(u8 *fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, checksums_info, CMP_MAP_W, fname);

  cksum_found = 1;

  close(fd);

  update_checkusms_local_map();

}

void update_checkusms_local_map() {

  s32 i, j;

  patched_cksums_total_num = patched_cksums_num = 0;

  for (i = 0; i < CMP_MAP_W / sizeof(u64); ++i) {

    if (((u64 *)checksums_info)[i]) {

      for (j = 0; j < sizeof(u64); ++j)
        if (checksums_info[i * sizeof(u64) + j]) {

          if (checksums_info[i * sizeof(u64) + j] != CK_NOT_UNDER_CONTROL) {

            cmp_patch_local_map[i * sizeof(u64) + j] = 0xff;
            ++patched_cksums_num;

          }

          ++patched_cksums_total_num;

        }

    }

  }

}

void write_patch_map(void) {

  u8 *fname;
  s32 fd;

  fname = alloc_printf("%s/patch_map", out_dir);
  fd    = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, checksums_info, CMP_MAP_W, fname);

  close(fd);
  ck_free(fname);

}

struct cks {

  u16 cmp_id;
  s32 first_idx;

};

static u8 light_exec(u8 *out_buf, s32 len) {

  write_to_testcase(out_buf, len);
  return run_light_target(exec_tmout);

}

static u8 heavy_exec(u8 *out_buf, s32 len, u32 target_cmp) {

  write_to_testcase(out_buf, len);
  return run_heavy_target(exec_tmout * HEAVY_TMOUT_MUL, target_cmp);

}

u8 fix_checksums(u32 exec_cksum, struct tags_info *tags, u8 *out_buf, s32 len,
                 u32 *ck_count, u8 must_crash) {

  DBGPRINT(" FIXING CHECKSUMS %d %d\n", patched_cksums_num,
           patched_cksums_total_num);

  if (!heavy_forksrv_pid) init_heavy_forkserver(heavy_argv);

  u8  ret = 1;
  s32 i, j, k, l;
  u32 cur_hash;
  u16 cmp_id   = 0;
  u8 *save_buf = NULL;

  struct tag *tmp_tags = ck_alloc_nozero(sizeof(struct tag) * len);
  memcpy(tmp_tags, tags->tags, len * sizeof(struct tag));

  struct cks *ordered = ck_alloc(sizeof(struct cks) * len);
  s32         ord_i   = 0;

  /*for (i = 0; i < len; ++i) {
  
    if (tmp_tags[i].flags & TAG_CMP_IS_CHECKSUM) {
      if (checksums_info[tmp_tags[i].cmp_id] == CK_NOT_UNDER_CONTROL ||
        cmp_patch_map[tmp_tags[i].cmp_id] == 0)
        continue;
      out_buf[i] = UR(256);
    }
  }*/

  /* Locate first level all checksums w/o depends_on */

  for (i = 0; i < len; ++i) {

    if ((tmp_tags[i].flags & TAG_CMP_IS_CHECKSUM) && !tmp_tags[i].depends_on) {

      if (cmp_id == tmp_tags[i].cmp_id) {

        bzero(&tmp_tags[i], sizeof(struct tag));
        continue;

      }

      cmp_id = tmp_tags[i].cmp_id;

      u8 present = 0;
      for (j = 0; j < ord_i; ++j) {

        if (ordered[j].cmp_id == cmp_id) {

          present = 1;
          break;

        }

      }

      if (present) {

        bzero(&tmp_tags[i], sizeof(struct tag));
        continue;

      }

      ordered[ord_i].cmp_id    = cmp_id;
      ordered[ord_i].first_idx = i;
      ++ord_i;

    }

  }

  DBGPRINT(" LEVEL 0 CHECKSUMS #%d\n", ord_i);

  u8 placed = 1;
  while (placed) {

    placed = 0;
    for (j = 0; j < ord_i; ++j) {

      cmp_id = 0;

      DBGPRINT(" GET DEPENDING ON CHECKSUM %x (%d)\n", ordered[j].cmp_id, j);

      for (i = 0; i < len; ++i) {

        if ((tmp_tags[i].flags & TAG_CMP_IS_CHECKSUM) &&
            tmp_tags[i].depends_on == ordered[j].cmp_id) {

          if (cmp_id == tmp_tags[i].cmp_id) {

            bzero(&tmp_tags[i], sizeof(struct tag));
            continue;

          }

          cmp_id = tmp_tags[i].cmp_id;

          u8 present = 0;
          for (k = 0; k < ord_i; ++k) {

            if (ordered[k].cmp_id == cmp_id) {

              present = 1;
              break;

            }

          }

          if (present) {

            bzero(&tmp_tags[i], sizeof(struct tag));
            continue;

          }

          DBGPRINT(" INSERTING CHECKSUM %x AT %d\n", cmp_id, ord_i);

          ordered[ord_i].cmp_id    = cmp_id;
          ordered[ord_i].first_idx = i;
          ++ord_i;

          placed = 1;

        }

      }

    }

  }

  /* get cmp vals (255 possibles) then, for the current, locate the correct j
     and replace with the right value.
     iterate until end. clear cmp_map at the end */

  /*common_light_fuzz_stuff(out_buf, len);
  exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  DBGPRINT(" ORIG hash: %x\n", exec_cksum);*/

  u8 force_unpatch = 1;

  s32 last_placed_idx = -1;

  u64 orig_hit_cnt, new_hit_cnt = 0;

  for (i = ord_i - 1; i >= 0; --i) {

    cmp_id = ordered[i].cmp_id;

    if (checksums_info[cmp_id] == CK_NOT_UNDER_CONTROL ||
        cmp_patch_map[cmp_id] == 0)
      continue;
    
    if (last_placed_idx != -1 && force_unpatch) {
      MEM_BARRIER();
      cmp_patch_map[ordered[last_placed_idx].cmp_id] = 0;
      MEM_BARRIER();
    }

    // orig_hit_cnt = queued_paths + unique_crashes;

    heavy_exec(out_buf, len, 0);

    // new_hit_cnt = queued_paths + unique_crashes;

    cur_hash = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    DBGPRINT(" >>>>>>> (%d %x) cmpid: %x [%d] --> old: %x new: %x\n", i,
             checksums_info[cmp_id], cmp_id, ordered[i].first_idx, exec_cksum, cur_hash);

    if (last_placed_idx != -1) {

      if (exec_cksum != cur_hash) {
      
        if (checksums_info[ordered[last_placed_idx].cmp_id] & CK_WARNING) {

          DBGPRINT(" %x NOT UNDER CONTROL\n", ordered[last_placed_idx].cmp_id);

          checksums_info[ordered[last_placed_idx].cmp_id] =
              CK_NOT_UNDER_CONTROL;
          cmp_patch_local_map[ordered[last_placed_idx].cmp_id] = 0;
          // cmp_patch_map[ordered[last_placed_idx].cmp_id] = 0;

          --patched_cksums_num;

          last_ckunpatch_time = get_cur_time();

        } else {

          DBGPRINT(" %x WARNING\n", ordered[last_placed_idx].cmp_id);
          checksums_info[ordered[last_placed_idx].cmp_id] |= CK_WARNING;

        }
        
        //if (patched_cksums_num) must_getdeps_asap = 3;

        goto exit_fix_cheksums;

      } else {

        checksums_info[ordered[last_placed_idx].cmp_id] &= ~CK_WARNING;

      }

    }

    for (l = 0; l < CMP_MAP_W; ++l) {

      struct cmp_header* h = &cmp_map->headers[i];

      if (likely(h->hits == 0)) continue;

      struct cmp_operands* col = cmp_map->log[i];

      if (h->id != cmp_id) {

        *((u64*)h) = 0;
        continue;

      }

      u32 hits = h->hits;

      DBGPRINT("   idx = %x hits = %u\n", l, hits);

      hits &= (CMP_MAP_H - 1);

      for (j = 0; j < hits; ++j) {

        u8 placed = 0;
        
        DBGPRINT("  cmp loc [%d] %lx %lx    %x\n", j, col[j].v0, col[j].v1, checksums_info[cmp_id]);
        
        if (col[j].v0 == col[j].v1) continue;

        for (k = 0 /*ordered[i].first_idx*/; k < len; ++k) {

          if (tags->tags[k].cmp_id != cmp_id ||
              !(tags->tags[k].flags & TAG_CMP_IS_CHECKSUM)) continue;

           DBGPRINT("    apply %d %lx\n", k, (*(u64*)&out_buf[k]));

          switch (checksums_info[cmp_id] & (~CK_WARNING)) {

            case CKTYPE_NORMAL8 | CK_IS_LEFT:
              if ((col[j].v0 & 0xff) == out_buf[k]) {

                out_buf[k] = col[j].v1 & 0xff;
                placed     = 1;

              }

              break;

            case CKTYPE_NORMAL16 | CK_IS_LEFT:
              if ((col[j].v0 & 0xffff) == *(u16 *)&out_buf[k]) {

                *(u16 *)&out_buf[k] = col[j].v1 & 0xffff;
                placed              = 1;

              }

              break;

            case CKTYPE_NORMAL32 | CK_IS_LEFT:
              if ((col[j].v0 & 0xffffffff) == *(u32 *)&out_buf[k]) {

                *(u32 *)&out_buf[k] = col[j].v1 & 0xffffffff;
                placed              = 1;

              }

              break;

            case CKTYPE_NORMAL64 | CK_IS_LEFT:
              if (col[j].v0 == *(u64 *)&out_buf[k]) {

                *(u64 *)&out_buf[k] = col[j].v1;
                placed              = 1;

              }

              break;

            case CKTYPE_SWAP16 | CK_IS_LEFT:
              if (SWAP16(col[j].v0 & 0xffff) == *(u16 *)&out_buf[k]) {

                *(u16 *)&out_buf[k] = SWAP16(col[j].v1 & 0xffff);
                placed              = 1;

              }

              break;

            case CKTYPE_SWAP32 | CK_IS_LEFT:
              if (SWAP32(col[j].v0 & 0xffffffff) == *(u32 *)&out_buf[k]) {

                *(u32 *)&out_buf[k] = SWAP32(col[j].v1 & 0xffffffff);
                placed              = 1;

              }

              break;

            case CKTYPE_SWAP64 | CK_IS_LEFT:
              if (SWAP64(col[j].v0) == *(u64 *)&out_buf[k]) {

                *(u64 *)&out_buf[k] = SWAP64(col[j].v1);
                placed              = 1;

              }

              break;

            case CKTYPE_NORMAL8 | CK_IS_RIGHT:
              if ((col[j].v1 & 0xff) == out_buf[k]) {

                out_buf[k] = col[j].v0 & 0xff;
                placed     = 1;

              }

              break;

            case CKTYPE_NORMAL16 | CK_IS_RIGHT:
              if ((col[j].v1 & 0xffff) == *(u16 *)&out_buf[k]) {

                *(u16 *)&out_buf[k] = col[j].v0 & 0xffff;
                placed              = 1;

              }

              break;

            case CKTYPE_NORMAL32 | CK_IS_RIGHT:
              if ((col[j].v1 & 0xffffffff) == *(u32 *)&out_buf[k]) {

                *(u32 *)&out_buf[k] = col[j].v0 & 0xffffffff;
                placed              = 1;

              }

              break;

            case CKTYPE_NORMAL64 | CK_IS_RIGHT:
              if (col[j].v1 == *(u64 *)&out_buf[k]) {

                *(u64 *)&out_buf[k] = col[j].v0;
                placed              = 1;

              }

              break;

            case CKTYPE_SWAP16 | CK_IS_RIGHT:
              if (SWAP16(col[j].v1 & 0xffff) == *(u16 *)&out_buf[k]) {

                *(u16 *)&out_buf[k] = SWAP16(col[j].v0 & 0xffff);
                placed              = 1;

              }

              break;

            case CKTYPE_SWAP32 | CK_IS_RIGHT:
              if (SWAP32(col[j].v1 & 0xffffffff) == *(u32 *)&out_buf[k]) {

                *(u32 *)&out_buf[k] = SWAP32(col[j].v0 & 0xffffffff);
                placed              = 1;

              }

              break;

            case CKTYPE_SWAP64 | CK_IS_RIGHT:
              if (SWAP64(col[j].v1) == *(u64 *)&out_buf[k]) {

                *(u64 *)&out_buf[k] = SWAP64(col[j].v0);
                placed              = 1;

              }

              break;

          }

          if (placed) {

            last_placed_idx = i;
            DBGPRINT("  placed!\n");
            break;

          }

        }

        if (!placed && hits < CMP_MAP_H) {
        
          if (checksums_info[ordered[i].cmp_id] & CK_WARNING) {

            DBGPRINT(" %x NOT UNDER CONTROL\n", ordered[i].cmp_id);

            checksums_info[ordered[i].cmp_id]      = CK_NOT_UNDER_CONTROL;
            cmp_patch_local_map[ordered[i].cmp_id] = 0;
            // cmp_patch_map[ordered[i].cmp_id] = 0;

            --patched_cksums_num;

            last_ckunpatch_time = get_cur_time();

          } else {

            DBGPRINT(" %x WARNING\n", ordered[i].cmp_id);
            checksums_info[ordered[i].cmp_id] |= CK_WARNING;

          }
          
          goto exit_fix_cheksums;
          
          /* HERE there is a checksum with only a cmp that cannot be reached
             from the input. An example is a libpng chunk with a too small size.
             Here we try to continue the fix without pretending to have the
             same trace_bits hash. */
          
          //if (patched_cksums_num) must_getdeps_asap = 3;

          //force_unpatch = 0;
          
          DBGPRINT("DON'T FORCE UNPATCH!\n");

        }

      }

      *((u64*)h) = 0;

    }

  }

  // memset(cmp_patch_map, 0, CMP_MAP_W);

  if (last_placed_idx != -1 && force_unpatch) {
    MEM_BARRIER();
    cmp_patch_map[ordered[last_placed_idx].cmp_id] = 0;
    MEM_BARRIER();
  }

  light_exec(out_buf, len);
  cur_hash = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  
  ret = exec_cksum != cur_hash;

  DBGPRINT(" LAST TRY --> old: %x new: %x\n", exec_cksum, cur_hash);

  if (last_placed_idx != -1) {

    if (exec_cksum != cur_hash) {
    
      if (checksums_info[ordered[last_placed_idx].cmp_id] & CK_WARNING) {

        DBGPRINT(" %x NOT UNDER CONTROL\n", ordered[last_placed_idx].cmp_id);

        checksums_info[ordered[last_placed_idx].cmp_id] = CK_NOT_UNDER_CONTROL;
        cmp_patch_local_map[ordered[last_placed_idx].cmp_id] = 0;
        // cmp_patch_map[ordered[last_placed_idx].cmp_id] = 0;

        --patched_cksums_num;

        last_ckunpatch_time = get_cur_time();

      } else {

        DBGPRINT(" %x WARNING\n", ordered[last_placed_idx].cmp_id);
        checksums_info[ordered[last_placed_idx].cmp_id] |= CK_WARNING;

      }
      
      //if (patched_cksums_num) must_getdeps_asap = 3;

      goto exit_fix_cheksums;

    } else {

      checksums_info[ordered[last_placed_idx].cmp_id] &= ~CK_WARNING;

    }

  }

  memset(cmp_patch_map, 0, CMP_MAP_W);

  u8 fault = light_exec(out_buf, len);
  cur_hash = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  
  DBGPRINT(" UNPATCH TRY --> old: %x new: %x\n", exec_cksum, cur_hash);

  if (exec_cksum != cur_hash && !must_crash) {

    for (i = 0; i < CMP_MAP_W; ++i) {

      if (likely(!checksums_info[i] ||
                 checksums_info[i] == CK_NOT_UNDER_CONTROL))
        continue;

      u8 present = 0;
      for (j = ord_i - 1; j >= 0; --j) {

        if (ordered[j].cmp_id == i) {

          present = 1;
          break;

        }

      }

      if (present) continue;

      /* Try to repatch the checksum and observe if it afflict the path
         without being in tags */
      MEM_BARRIER();
      cmp_patch_map[i] = 0xff;
      MEM_BARRIER();

      u8  fault    = light_exec(out_buf, len);
      u32 new_hash = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      MEM_BARRIER();
      cmp_patch_map[i] = 0;
      MEM_BARRIER();

      if (cur_hash != new_hash) {
      
        /* Ignore warning here */
        if (checksums_info[i] & CK_WARNING) {

          DBGPRINT(" %x NOT UNDER CONTROL\n", i);

          checksums_info[i]      = CK_NOT_UNDER_CONTROL;
          cmp_patch_local_map[i] = 0;

          --patched_cksums_num;

          last_ckunpatch_time = get_cur_time();

        } else {

          checksums_info[i] |= CK_WARNING;

        }
        
        //if (patched_cksums_num) must_getdeps_asap = 3;

      }

    }

  }

  if (must_crash && fault != FAULT_CRASH) ret = 1;

exit_fix_cheksums:

  if (save_buf) ck_free(save_buf);

  memcpy(cmp_patch_map, cmp_patch_local_map, CMP_MAP_W);

  *ck_count = ord_i;

  return ret;

}

u8 do_not_fix_crashes = 0;

void crashes_reconciliation(void) {

  struct crash_qentry *cq = crashes_queue;
  u8 *                 fn;

  dont_save_interesting = 1;

  while (cq) {

    u32 exec_cksum;

    if (do_not_fix_crashes) goto process_crash;

    struct tags_info *ti = produce_checksums_tags(cq->mem, cq->len);
    if (ti == NULL) {

      DBGPRINT("\n");
      DBGPRINT(" FAILED TO CRASH GETDEPS");
      DBGPRINT("\n");
      DBGPRINT("\n");

      goto next_crash_in_queue;

    }

    u32 ck_count;

    ++crash_fix_total;

    if (fix_checksums(exec_cksum, ti, cq->mem, cq->len, &ck_count, 1)) {

      DBGPRINT("\n");
      DBGPRINT(" FAILED TO FIX CRASH CHECKSUMS");
      DBGPRINT("\n");
      DBGPRINT("\n");

      goto next_crash_in_queue;

    }

    ++crash_fix;

    DBGPRINT("\n");
    DBGPRINT(" CRASH CHECKSUMS OKKKKK");
    DBGPRINT("\n");
    DBGPRINT("\n");

  process_crash:

    memcpy(trace_bits, cq->saved_bits, MAP_SIZE);

    /* This also do update */
    if (!has_new_bits(virgin_crash)) goto next_crash_in_queue;

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                      unique_crashes, cq->kill_signal, cq->description);

#else

    fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                      kill_signal);

#endif /* ^!SIMPLE_FILES */

    unique_crashes++;

    last_crash_time  = cq->last_crash_time;
    last_crash_execs = cq->last_crash_execs;

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, cq->mem, cq->len, fn);
    close(fd);

    ck_free(fn);

  next_crash_in_queue:

    ck_free(cq->mem);
    ck_free(cq->description);

    struct crash_qentry *cq_prev = cq;
    cq                           = cq->next;

    ck_free(cq_prev);

  }

  dont_save_interesting = 0;
  crashes_queue         = NULL;

  memcpy(virgin_tmp_crash, virgin_crash, MAP_SIZE);

}

