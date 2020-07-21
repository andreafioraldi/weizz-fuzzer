#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <unistd.h>
#include <pthread.h>

#include "weizz-llvm.h"

__attribute__((visibility("default"))) __attribute__((used))
const char* const LIBWEIZZ_module_instrument = "LIBWEIZZ_module_instrument";

#define ATTR_UNUSED __attribute__((unused))

__thread size_t cmp_counter;

struct cmp_map empty_heavy_map;
struct cmp_map* heavy_map = &empty_heavy_map;

uint8_t empty_light_map[MAP_SIZE];
uint8_t* light_map = empty_light_map;

uint8_t* cmp_patch_map;

unsigned int weizz_forksrv_pid;
uint8_t weizz_fork_child;

int ctx_sensitive;
int enable_cmp_patching;
int is_persistent;

int weizz_is_initialized;

static void weizz_setup(void) {

  if (weizz_is_initialized) return;
  weizz_is_initialized = 1;
  
  if(getenv("WEIZZ_ENABLE_PATCHING"))
    enable_cmp_patching = 1;

  char *id_str = getenv(LIGHT_SHM_ENV_VAR);
  if(!id_str)
    id_str = getenv("__AFL_SHM_ID");
  if(id_str) {

    int shm_id = atoi(id_str);
    light_map = (uint8_t*)shmat(shm_id, NULL, 0);

    if (light_map == (uint8_t*)-1)
      exit(1);

    if (getenv("__WEIZZ_HEAVY__")) {
        id_str = getenv(HEAVY_SHM_ENV_VAR);
        if(!id_str)
          exit(1);

        shm_id = atoi(id_str);
        heavy_map = (void*)shmat(shm_id, NULL, 0);

        if (heavy_map == (void*)-1)
          exit(1);
    }

    if (enable_cmp_patching) {
      // NOT SUPPORTED

      id_str = getenv(PATCH_SHM_ENV_VAR);
      if(!id_str)
        exit(1);
      
      shm_id = atoi(id_str);
      cmp_patch_map = (uint8_t*)shmat(shm_id, NULL, 0);

      if (cmp_patch_map == (uint8_t*)-1)
        exit(1);
    }
    
  }

}

/* Fork server logic. */

static void weizz_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;
  
  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {
        signal(SIGCHLD, old_sigchld_handler);

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}

/* A simplified persistent mode handler. */

int __weizz_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {
  
    if (is_persistent) {

      memset(light_map, 0, MAP_SIZE);
      memset(heavy_map, 0, sizeof(struct cmp_map));
      light_map[0] = 1;
      //prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;
  }

  if (--cycle_cnt) {

    raise(SIGSTOP);

    light_map[0] = 1;
    //prev_loc = 0;

    return 1;
  }

  return 0;
}


u8 init_done;
void __weizz_manual_init(void) {

  if (!init_done) {
  
    weizz_setup();
    weizz_start_forkserver();
    init_done = 1;

  }

}

__attribute__((constructor)) void __weizz_auto_init(void) {
    
  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __weizz_manual_init();

}


/*
 * -finstrument-functions
 */
void __cyg_profile_func_enter(void* func, void* caller) {
    
}

void __cyg_profile_func_exit(
    void* func ATTR_UNUSED, void* caller ATTR_UNUSED) {
    
}

/*
 * -fsanitize-coverage=trace-pc
 */

#define weizz_log_br(idx) light_map[idx]++

void __sanitizer_cov_trace_pc(void) {
  
  /*uintptr_t cur_loc = (uintptr_t)__builtin_return_address(0);
  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;
  weizz_log_br(cur_loc);*/

}

/*
 * -fsanitize-coverage=trace-cmp
 */

static inline void weizz_log_cmp(
    uintptr_t pc, uint64_t Arg1, uint64_t Arg2, int shape) {
    
  uintptr_t k = (pc >> 4) ^ (pc << 8);
  k &= WMAP_WIDTH - 1; 
  
  heavy_map->headers[k].id = k;
  
  u32 hits = heavy_map->headers[k].hits;
  heavy_map->headers[k].hits = hits + 1;
  if (!heavy_map->headers[k].cnt)
    heavy_map->headers[k].cnt = cmp_counter++;

  heavy_map->headers[k].shape = shape;

  hits &= CMP_MAP_H - 1;
  heavy_map->log[k][hits].v0 = Arg1;
  heavy_map->log[k][hits].v1 = Arg2;
  
  heavy_map->headers[k].type = CMP_TYPE_INS;

}

void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
  if (heavy_map) weizz_log_cmp((uintptr_t)__builtin_return_address(0), Arg1, Arg2, 0);
}

void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
  if (heavy_map) weizz_log_cmp((uintptr_t)__builtin_return_address(0), Arg1, Arg2, 1);
}

void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
  if (heavy_map) weizz_log_cmp((uintptr_t)__builtin_return_address(0), Arg1, Arg2, 3);
}

void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
  if (heavy_map) weizz_log_cmp((uintptr_t)__builtin_return_address(0), Arg1, Arg2, 7);
}

/*
 * Const versions of trace_cmp, we don't use any special handling for these
 *
 * For MacOS, these're weak aliases, as Darwin supports only them
 */

#if defined(__APPLE__)
#pragma weak __sanitizer_cov_trace_const_cmp1 = __sanitizer_cov_trace_cmp1
#pragma weak __sanitizer_cov_trace_const_cmp2 = __sanitizer_cov_trace_cmp2
#pragma weak __sanitizer_cov_trace_const_cmp4 = __sanitizer_cov_trace_cmp4
#pragma weak __sanitizer_cov_trace_const_cmp8 = __sanitizer_cov_trace_cmp8
#else
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp1")));
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp2")));
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp4")));
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp8")));
#endif /* defined(__APPLE__) */

/*
 * Cases[0] is number of comparison entries
 * Cases[1] is length of Val in bits
 */
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t* Cases) {
    if (heavy_map) 
      for (uint64_t i = 0; i < Cases[0]; i++) {
          uintptr_t pos = (uintptr_t)__builtin_return_address(0) + i;
          weizz_log_cmp(pos, Val, Cases[i + 2], 7);
      }
}

/*
 * Old version of __sanitizer_cov_trace_cmp[n]. Remove it at some point
 */
/*void __sanitizer_cov_trace_cmp(
    uint64_t SizeAndType, uint64_t Arg1, uint64_t Arg2) {
    weizz_log_cmp((uintptr_t)__builtin_return_address(0), Arg1, Arg2, 7);
}*/

/*
 * gcc-8 -fsanitize-coverage=trace-cmp trace hooks
 */
void __sanitizer_cov_trace_cmpf(
    float __attribute__((unused)) Arg1, float __attribute__((unused)) Arg2) {
}
void __sanitizer_cov_trace_cmpd(
    double __attribute__((unused)) Arg1, double __attribute__((unused)) Arg2) {
}


/*
 * -fsanitize-coverage=indirect-calls
 */
void __sanitizer_cov_trace_pc_indir(uintptr_t callee) {

  /*uintptr_t prev_loc = (uintptr_t)__builtin_return_address(0);
  prev_loc = (prev_loc >> 4) ^ (prev_loc << 8);
  prev_loc &= MAP_SIZE - 1;

  uintptr_t cur_loc = callee;
  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  weizz_log_br(cur_loc ^ prev_loc);*/

}

/*
 * In LLVM-4.0 it's marked (probably mistakenly) as non-weak symbol, so we need to mark it as weak
 * here
 */
__attribute__((weak)) void __sanitizer_cov_indir_call16(
    void* callee, void* callee_cache16[] ATTR_UNUSED) {

  /*uintptr_t prev_loc = (uintptr_t)__builtin_return_address(0);
  prev_loc = (prev_loc >> 4) ^ (prev_loc << 8);
  prev_loc &= MAP_SIZE - 1;

  uintptr_t cur_loc = (uintptr_t)callee;
  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  weizz_log_br(cur_loc ^ prev_loc);*/

}

#define R(x) (random() % (x))

/*
 * -fsanitize-coverage=trace-pc-guard
 */
uint32_t progressive = 0;
void __sanitizer_cov_trace_pc_guard_init(
    uint32_t* start, uint32_t* stop) {

  unsigned inst_ratio = 100;
  char* x;

  if (start == stop || *start) return;

  /*x = getenv("WEIZZ_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {

    fprintf(stderr, "[-] ERROR: Invalid WEIZZ_INST_RATIO (must be 1-100).\n");
    abort();

  }*/

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  /**(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio)
      *start = R(MAP_SIZE - 1) + 1;
    else
      *start = 0;

    start++;

  }*/
  
  *(start++) = (progressive++) & (MAP_SIZE - 1);

  while (start < stop) {

    *start = (progressive++) & (MAP_SIZE - 1);
    start++;

  }
  
}

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
    weizz_log_br(*guard);
}

