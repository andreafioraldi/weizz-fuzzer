/*
   weizz - queue related functions
   -------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include <sys/sendfile.h>
#include "weizz.h"

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

void mark_as_variable(struct queue_entry *q) {

  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn    = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry *q, u8 state) {

  u8 *fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state) {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}

/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

void cull_queue(void) {

  struct queue_entry *q;
  static u8           temp_v[MAP_SIZE >> 3];
  u32                 i;

  if (!score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  while (q) {

    q->favored = 0;
    q          = q->next;

  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--)
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;

    }

  q = queue;

  while (q) {

    mark_as_redundant(q, !q->favored);
    q = q->next;

  }

}

/* Append new test case to the queue. */

void add_to_queue(u8 *fname, u32 len, u8 passed_det) {

  struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

  q->fname      = fname;
  q->len        = len;
  q->depth      = cur_depth + 1;
  q->passed_det = passed_det;

  if (cksum_patched) q->must_fix_checksums = 1;

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {

    queue_top->next = q;
    queue_top       = q;

  } else

    q_prev100 = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  if (!(queued_paths % 100)) {

    q_prev100->next_100 = q;
    q_prev100           = q;

  }

  last_path_time = get_cur_time();

}

void add_to_tg_queue(struct queue_entry *q) {

  if (q->tg_queued) return;
  
  q->tg_queued = 1;

  if (tg_queue_top) {

    tg_queue_top->tg_next = q;
    tg_queue_top          = q;

  } else

    tg_q_prev100 = tg_queue = tg_queue_top = q;

  ++tg_queued_num;

  if (!(tg_queued_num % 100)) {

    tg_q_prev100->tg_next_100 = q;
    tg_q_prev100              = q;

  }

}

/* Destroy the entire queue. */

void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;

  }

}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(struct queue_entry *q) {

  u8 *fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;

}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers() {

  DIR *          sd;
  struct dirent *sd_ent;
  u32            sync_cnt = 0;
  u64            prev_queued;

  sd = opendir(sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;
  cur_depth             = 0;

  /* Look at the entries created for every other fuzzer in the sync directory.
   */

  while ((sd_ent = readdir(sd))) {

    static u8 stage_tmp[128];

    DIR *          qd, *td;
    struct dirent *qd_ent;
    u8 *           qd_path, *qd_synced_path, *tg_path;
    u32            min_accept = 0, next_min_accept;

    u8  have_tags_dir = 0;
    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {

      ck_free(qd_path);
      continue;

    }

    tg_path = alloc_printf("%s/%s/tags", sync_dir, sd_ent->d_name);

    if (td = opendir(tg_path)) {

      closedir(td);
      have_tags_dir = 1;

    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur  = 0;
    stage_max  = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked
       at it before; exec a test case if not. */

    while ((qd_ent = readdir(qd))) {

      u8 *        path;
      s32         fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 ||
          syncing_case < min_accept)
        continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (syncing_case >= next_min_accept) next_min_accept = syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) {

        ck_free(path);
        continue;

      }

      if (fstat(fd, &st)) PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(mem, st.st_size);

        fault = run_light_target(exec_tmout);

        if (stop_soon) return;

        prev_queued = queued_paths;

        syncing_party = sd_ent->d_name;
        queued_imported += save_if_interesting(mem, st.st_size, fault);
        syncing_party = 0;

        if (have_tags_dir && prev_queued != queued_paths) {

          u8 *tgpath = alloc_printf("%s/%s", tg_path, qd_ent->d_name);

          queue_top->sync_tags_fname = tgpath;
          queue_top->sync_fname      = ck_strdup(path);

          if (access(tgpath, F_OK) != -1) {

            queue_top->tags_fname = alloc_printf(
                "%s/tags/%s", out_dir, strrchr(queue_top->fname, '/') + 1);

            s32 dest_fd = locked_open_mode(queue_top->tags_fname,
                                           O_WRONLY | O_CREAT | O_EXCL, 0600);
            s32 src_fd  = locked_open(tgpath, O_RDONLY);

            struct stat src_stat;
            fstat(src_fd, &src_stat);

            /* Be robust */
            if ((sizeof(struct tags_info) + sizeof(struct tag) * queue_top->len) ==
                src_stat.st_size) {

              sendfile(dest_fd, src_fd, NULL, src_stat.st_size);
              close(dest_fd);

              queue_top->use_derived_tags = 1;

              add_to_tg_queue(queue_top);

            } else {

              close(dest_fd);
              unlink(queue_top->tags_fname);

              ck_free(queue_top->tags_fname);
              queue_top->tags_fname = NULL;

            }

            close(src_fd);

          }

        }

        munmap(mem, st.st_size);

        if (!(stage_cur++ % stats_update_freq)) show_stats();

      }

      ck_free(path);
      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(tg_path);
    ck_free(qd_synced_path);

  }

  closedir(sd);

}

void update_synced(struct queue_entry *q) {

  if (!q->sync_tags_fname) return;

  if (access(q->sync_tags_fname, F_OK) < 0) return;

  s32 src_fd = locked_open(q->sync_tags_fname, O_RDONLY);

  struct stat src_stat;
  fstat(src_fd, &src_stat);

  u8 *buf       = ck_alloc_nozero(src_stat.st_size);
  u32 tags_size = src_stat.st_size;
  ck_read(src_fd, buf, tags_size, q->sync_tags_fname);

  close(src_fd);

  u8 must_update   = 0;
  u8 must_tg_queue = 0;

  if (q->tags_fname) {

    s32         t_fd = locked_open(q->tags_fname, O_RDONLY);
    struct stat t_stat;
    fstat(t_fd, &t_stat);

    must_update = t_stat.st_mtim.tv_sec < src_stat.st_mtim.tv_sec;

    close(t_fd);

  } else {

    must_update = 1;
    q->tags_fname =
        alloc_printf("%s/tags/%s", out_dir, strrchr(q->fname, '/') + 1);
    must_tg_queue = 1;

  }

  if (!must_update) {

    ck_free(buf);
    return;

  }

  src_fd = locked_open(q->sync_fname, O_RDONLY);

  fstat(src_fd, &src_stat);

  if (sizeof(struct tags_info) + sizeof(struct tag) * src_stat.st_size != tags_size) {

    close(src_fd);
    ck_free(buf);

    if (must_tg_queue) {

      ck_free(q->tags_fname);
      q->tags_fname = NULL;

    }

    return;

  }

  s32 dest_fd = locked_open_mode(q->fname, O_WRONLY | O_TRUNC | O_CREAT, 0600);

  sendfile(dest_fd, src_fd, NULL, src_stat.st_size);

  q->len = src_stat.st_size;

  close(src_fd);
  close(dest_fd);

  dest_fd = locked_open_mode(q->tags_fname, O_WRONLY | O_TRUNC | O_CREAT, 0600);

  ck_write(dest_fd, buf, tags_size, q->tags_fname);

  close(dest_fd);

  q->use_derived_tags = 1;

  if (must_tg_queue) add_to_tg_queue(q);

  ck_free(buf);

}

