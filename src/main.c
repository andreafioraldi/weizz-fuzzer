/*
   weizz - fuzzer main
   -------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_MAIN
#include "weizz.h"

u8 *external_cksum_info;

/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char **argv) {

  u32 len = 1, i;
  u8 *buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;

  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++) {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';

  }

  *buf = 0;

}

/* Display usage hints. */

void usage(u8 *argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n\n"

      "  -i dir        - input directory with test cases\n"
      "  -o dir        - output directory for fuzzer findings\n\n"

      "Execution control settings:\n\n"

      "  -f file       - location read by the fuzzed program (stdin)\n"
      "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
      "  -m megs       - memory limit for child process (%u MB)\n"
      "  -L bytes      - size bounds to disable getdeps for a testcase\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

      "Fuzzing behavior settings:\n\n"

      "  -F            - full weizz mode, always perform surgical fuzzing\n"
      "  -b            - force getdeps with bit flips, more accuracy\n"
      "  -A            - aggressive mode, always enter in getdeps when "
      "pending_favs = 0\n"
      "  -w            - smart mode, high-order mutate tagged inputs\n"
      "  -h            - stacking mode, alternate smart and AFL mutations\n"
      "  -l            - enable the locked havoc stage when surgical "
      "fuzzing\n"
      "  -G            - after the getdeps stage stop fuzzing the current "
      "entry\n"
      "  -c            - enable checksum patching\n"
      "  -a            - avoid the get deps stage, almost like standard AFL\n"
      "  -u            - disable the trim stage (use with uninformed inputs)\n"
      "  -d            - quick & dirty mode (skips deterministic steps)\n"
      "  -x dir        - optional fuzzer dictionary (see README)\n\n"

      "Other stuff:\n\n"

      "  -P patch_map  - load a checksums information map\n"
      "  -T text       - text banner to show on the screen\n"
      "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
      "  -e ext        - file extension for the temporarily generated test\n"
      "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

      "For additional tips, please consult README.\n\n",

      argv0, EXEC_TIMEOUT, MEM_LIMIT);

  exit(1);

}

/* Detect @@ in args. */

void detect_file_args(char **argv) {

  u32 i   = 0;
  u8 *cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8 *aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file) {

        if (file_extension) {

          out_file = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);

        } else {

          out_file = alloc_printf("%s/.cur_input", out_dir);

        }

      }

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/')
        aa_subst = out_file;
      else
        aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg   = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd);                                                 /* not tracked */

}

/* Rewrite argv for weizz. */

static char **get_weizz_qemu_argv(u8 *own_loc, char **argv, int argc,
                                  char *qemu_bin) {

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
  u8 *   tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char *) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";
  
  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("WEIZZ_PATH");

  if (tmp) {

    cp = alloc_printf("%s/%s", tmp, qemu_bin);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    new_argv[0] = cp;

    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl      = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/%s", own_copy, qemu_bin);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s/%s'", own_copy, qemu_bin);

    new_argv[0] = cp;

    ck_free(own_copy);
    return new_argv;

  } else

    ck_free(own_copy);

  FATAL("Failed to locate '%s'.", qemu_bin);
  return NULL;

}

/* Main entry point */

int main(int argc, char **argv) {

  s32    opt;
  u64    prev_queued       = 0;
  u32    sync_interval_cnt = 0, seek_to;
  u8 *   extras_dir        = 0;
  u8     mem_limit_given   = 0;
  u8     exit_1            = !!getenv("WEIZZ_BENCH_JUST_ONE");
  char **use_argv;

  struct timeval  tv;
  struct timezone tz;

  // setenv("WEIZZ_CTX_SENSITIVE", "1", 1);

  SAYF(cCYA "weizz " cBRI VERSION cRST " by <andreafioraldi@gmail.com>\n");

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  while ((opt = getopt(argc, argv,
                       "+i:o:f:m:t:L:T:dCB:S:M:x:QFbAEwhlgcauP:De:QH:")) > 0)

    switch (opt) {
    
      case 'H': {
      
        heavy_binary = ck_strdup(optarg);
        break;
      
      }

      case 'i':                                                /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      case 'o':                                               /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M': {                                         /* master sync ID */

        u8 *c;

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);

        if ((c = strchr(sync_id, ':'))) {

          *c = 0;

          if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
              !master_id || !master_max || master_id > master_max ||
              master_max > 1000000)
            FATAL("Bogus master ID passed to -M");

        }

        force_deterministic = 1;

      }

      break;

      case 'S':

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);
        break;

      case 'f':                                              /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 'x':                                               /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': {                                                /* timeout */

        u8 suffix = 0;

        if (timeout_given) FATAL("Multiple -t options not supported");

        if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -t");

        if (exec_tmout < 5) FATAL("Dangerously low value of -t");

        if (suffix == '+')
          timeout_given = 2;
        else
          timeout_given = 1;

        break;

      }

      case 'm': {                                              /* mem limit */

        u8 suffix = 'M';

        if (mem_limit_given) FATAL("Multiple -m options not supported");
        mem_limit_given = 1;

        if (!strcmp(optarg, "none")) {

          mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -m");

        switch (suffix) {

          case 'T': mem_limit *= 1024 * 1024; break;
          case 'G': mem_limit *= 1024; break;
          case 'k': mem_limit /= 1024; break;
          case 'M': break;

          default: FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (mem_limit < 5) FATAL("Dangerously low value of -m");

        if (sizeof(rlim_t) == 4 && mem_limit > 2000)
          FATAL("Value of -m out of range on 32-bit systems");

      }

      break;

      case 'L': {                                     /* getdeps size limit */

        u8 suffix = 'M';

        if (getdeps_size_limit) FATAL("Multiple -L options not supported");

        if (!strcmp(optarg, "none")) {

          getdeps_size_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &getdeps_size_limit, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -L");

        switch (suffix) {

          case 'k': getdeps_size_limit *= 1024; break;
          case 'M': getdeps_size_limit *= 1024 * 1024; break;
          case 'G':
            getdeps_size_limit *= 1024 * 1024 * 1024;
            ;
            break;

          default: FATAL("Unsupported suffix or bad syntax for -L");

        }

        break;

      }

      case 'd':                                       /* skip deterministic */

        if (skip_deterministic)
          FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing       = 1;
        break;

      case 'B':                                              /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (in_bitmap) FATAL("Multiple -B options not supported");

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'C':                                               /* crash mode */

        if (crash_mode) FATAL("Multiple -C options not supported");
        crash_mode = FAULT_CRASH;
        break;

      case 'T':                                                   /* banner */

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      case 'F':                                          /* full_weizz_mode */

        if (full_weizz_mode) FATAL("Multiple -F options not supported");
        full_weizz_mode = 1;

        break;

      case 'b':                                       /* force_bits_getdeps */

        if (force_bits_getdeps) FATAL("Multiple -b options not supported");
        force_bits_getdeps = 1;

        break;

      case 'A':                                         /* aggressive weizz */

        if (aggressive_weizz) FATAL("Multiple -A options not supported");
        aggressive_weizz = 1;

        break;

      case 'w':                                       /* SMART FUZZING mode */
        if (smart_mode) FATAL("Multiple -w options not supported");
        smart_mode         = 1;
        break;

      case 'h':
        if (stacking_mutation_mode) FATAL("Multipe -h options not supported");
        stacking_mutation_mode = 1;
        break;

      case 'l':
        if (enable_locked_havoc) FATAL("Multipe -l options not supported");
        enable_locked_havoc = 1;
        break;

      case 'G':
        if (discard_after_getdeps) FATAL("Multipe -G options not supported");
        discard_after_getdeps = 1;
        break;

      case 'c':
        if (enable_checksum_recovery) FATAL("Multipe -c options not supported");
        enable_checksum_recovery = 1;
        break;

      case 'a':
        if (avoid_getdeps) FATAL("Multiple -a options not supported");
        avoid_getdeps = 1;
        break;

      case 'u':
        if (avoid_trim) FATAL("Multiple -u options not supported");
        avoid_trim = 1;
        break;

      case 'P':
        if (has_read_ckinfo) FATAL("Multiple -P options not supported");
        if (access(optarg, F_OK) != -1)
          read_patch_map(optarg);
        else
          WARNF("Specified patch_map (%s) file not found.", optarg);
        external_cksum_info = ck_strdup(optarg);
        has_read_ckinfo     = 1;
        break;

      case 'e':

        if (file_extension) FATAL("Multiple -e options not supported");
        file_extension = optarg;
        break;
      
      case 'Q':
        
        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;
        break;

      default: usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  if (!avoid_getdeps && force_deterministic)
    force_deterministic = 0;
  
  if (!avoid_getdeps) {
    skip_deterministic = 1;
    //use_splicing       = 1;
  }
  
  if (qemu_mode && heavy_binary)
    FATAL("-H and -Q are mutually exclusive");
  
  if (!qemu_mode && !avoid_getdeps && !heavy_binary)
    FATAL("If you don't specify -H you have to use -Q or -a");
  
  if (enable_checksum_recovery && !qemu_mode) {
    FATAL("Checksum patching is available only in QEMU mode");
  }
  
  /* enforce qemu mode */
  if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

  setup_signal_handlers();

  if (sync_id) fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if (getenv("WEIZZ_NO_CPU_RED")) no_cpu_meter_red = 1;
  if (getenv("WEIZZ_NO_ARITH")) no_arith = 1;
  if (getenv("WEIZZ_SHUFFLE_QUEUE")) shuffle_queue = 1;
  if (getenv("WEIZZ_FAST_CAL")) fast_cal = 1;

  if (getenv("WEIZZ_HANG_TMOUT")) {

    hang_tmout = atoi(getenv("WEIZZ_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of WEIZZ_HANG_TMOUT");

  }

  if (getenv("WEIZZ_PRELOAD")) {

    setenv("LD_PRELOAD", getenv("WEIZZ_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("WEIZZ_PRELOAD"), 1);

  }

  if (getenv("WEIZZ_LD_PRELOAD"))
    FATAL("Use WEIZZ_PRELOAD instead of WEIZZ_LD_PRELOAD");

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_shm();
  init_count_class16();

  if (in_place_resume) {

    u8 *fn = alloc_printf("%s/%s", out_dir, "pass_stats");
    if (!access(fn, F_OK)) read_pass_stats(fn);
    ck_free(fn);

    if (!has_read_ckinfo) {

      fn = alloc_printf("%s/%s", out_dir, "patch_map");
      if (!access(fn, F_OK)) read_patch_map(fn);
      ck_free(fn);

    }

  }

  if (cksum_found && enable_checksum_recovery) {

    memcpy(cmp_patch_map, cmp_patch_local_map, WMAP_WIDTH);
    cksum_patched = 1;

  }

  setup_dirs_fds();
  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir) load_extras(extras_dir);

  if (!timeout_given) find_timeout();

  detect_file_args(argv + optind + 1);

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode) {
    heavy_argv = light_argv = get_weizz_qemu_argv(argv[0], argv + optind,
                                                  argc - optind, "weizz-qemu");
  } else {
    heavy_argv = light_argv = argv + optind;  
  }

  perform_dry_run();

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty) {

    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;

  }

  while (1) {

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {

      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {

        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;

      }

      show_stats();

      if (not_on_tty) {

        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);

      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing)
          cycles_wo_finds++;
        else
          use_splicing = 1;

      } else

        cycles_wo_finds = 0;

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("WEIZZ_IMPORT_FIRST"))
        sync_fuzzers();

    }

    skipped_fuzz = fuzz_one();

    if (crashes_queue) crashes_reconciliation();

    if (avoid_getdeps && external_cksum_info &&
        access(external_cksum_info, F_OK) != -1) {

      read_patch_map(external_cksum_info);

      if (cksum_found && enable_checksum_recovery) {

        memcpy(cmp_patch_map, cmp_patch_local_map, WMAP_WIDTH);
        cksum_patched = 1;

      }

    }

    if (!stop_soon && sync_id && !skipped_fuzz && !must_getdeps_asap) {

      if (!(sync_interval_cnt++ % SYNC_INTERVAL)) sync_fuzzers();

    }

    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    current_entry++;

  }

  if (queue_cur) show_stats();

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see README.)\n");

  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

