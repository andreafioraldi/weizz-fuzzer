/*
   weizz - signal handlers
   -----------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Based on afl-fuzz by Michal Zalewski <lcamtuf@google.com>

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include "weizz.h"

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1;

  if (light_child_pid > 0) kill(light_child_pid, SIGKILL);
  if (heavy_child_pid > 0) kill(heavy_child_pid, SIGKILL);
  if (light_forksrv_pid > 0) kill(light_forksrv_pid, SIGKILL);
  if (heavy_forksrv_pid > 0) kill(heavy_forksrv_pid, SIGKILL);

}

/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  skip_requested = 1;

}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  if (light_child_pid > 0) {

    child_timed_out = 1;
    kill(light_child_pid, SIGKILL);

  } else if (light_child_pid == -1 && light_forksrv_pid > 0) {

    child_timed_out = 1;
    kill(light_forksrv_pid, SIGKILL);

  }

  if (heavy_child_pid > 0) {

    child_timed_out = 1;
    kill(heavy_child_pid, SIGKILL);

  } else if (heavy_child_pid == -1 && heavy_forksrv_pid > 0) {

    child_timed_out = 1;
    kill(heavy_forksrv_pid, SIGKILL);

  }

}

/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {

  clear_screen = 1;

}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}

