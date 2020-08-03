/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/tb-lookup.h"
#include "exec/log.h"
#include "qemu/main-loop.h"
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
#include "hw/i386/apic.h"
#endif
#include "sysemu/cpus.h"
#include "sysemu/replay.h"

/* weizz */

#include "weizz-qemu.h"
#include "pmparser.h"
#include <sys/shm.h>

unsigned int weizz_forksrv_pid;
unsigned char weizz_fork_child;

uint8_t* light_map;
uint8_t* cmp_patch_map;

int enable_cmp_patching;
target_ulong weizz_target_cmp;

int is_heavy;
int ctx_sensitive;

__thread abi_ulong prev_loc;
__thread size_t cmp_counter;

unsigned int weizz_inst_rms = MAP_SIZE;

abi_ulong    weizz_persistent_addr, weizz_persistent_ret_addr;
unsigned int weizz_persistent_cnt;
unsigned char is_persistent;
target_long   persistent_stack_offset;

struct cmp_map* heavy_map;
target_ulong weizz_target_branch;

struct weizz_tb {
  target_ulong pc;
  target_ulong cs_base;
  uint32_t flags;
  uint32_t cf_mask;
};

struct weizz_tsl {
  struct weizz_tb tb;
  char is_chain;
};

struct weizz_chain {
  struct weizz_tb last_tb;
  uint32_t cf_mask;
  int tb_exit;
};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int, uint32_t);
static inline void tb_add_jump(TranslationBlock *tb, int n, TranslationBlock *tb_next);

/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it, or when it
   decides to chain two TBs together. When this happens, we tell the parent to
   mirror the operation, so that the next fork() has a cached copy. */

static void weizz_request_tsl(target_ulong pc, target_ulong cb, uint32_t flags, uint32_t cf_mask,
                            TranslationBlock *last_tb, int tb_exit) {

  struct weizz_tsl t;
  struct weizz_chain c;

  if (!weizz_fork_child) return;

  t.tb.pc      = pc;
  t.tb.cs_base = cb;
  t.tb.flags   = flags;
  t.tb.cf_mask = cf_mask;
  t.is_chain   = (last_tb != NULL);

  if (write(TSL_FD, &t, sizeof(struct weizz_tsl)) != sizeof(struct weizz_tsl))
    return;

  if (t.is_chain) {
    c.last_tb.pc      = last_tb->pc;
    c.last_tb.cs_base = last_tb->cs_base;
    c.last_tb.flags   = last_tb->flags;
    c.cf_mask         = cf_mask;
    c.tb_exit         = tb_exit;

    if (write(TSL_FD, &c, sizeof(struct weizz_chain)) != sizeof(struct weizz_chain))
      return;
  }

}

static inline int is_valid_addr_pc(target_ulong addr) {

    int l, flags;
    target_ulong page;
    void * p;
    
    page = addr & TARGET_PAGE_MASK;
    l = (page + TARGET_PAGE_SIZE) - addr;
    
    flags = page_get_flags(page);
    if (!(flags & PAGE_VALID) || !(flags & PAGE_READ))
        return 0;
    
    return 1;
}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void weizz_wait_tsl(CPUState *cpu, int fd)
{

  struct weizz_tsl t;
  struct weizz_chain c;
  TranslationBlock *tb, *last_tb;

  while (1) {
    
    uint8_t invalid_pc = 0;

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct weizz_tsl)) != sizeof(struct weizz_tsl))
      break;
      
    if (t.tb.pc == (target_ulong)(-1)) return;

    tb = tb_htable_lookup(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);

    if(!tb) {
    
      if (is_valid_addr_pc(t.tb.pc)) {
    
        mmap_lock();
        tb = tb_gen_code(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, 0);
        mmap_unlock();
      } else {
      
        invalid_pc = 1; 
      }
    }

    if (t.is_chain) {
      if (read(fd, &c, sizeof(struct weizz_chain)) != sizeof(struct weizz_chain))
        break;

      if (!invalid_pc) {

        last_tb = tb_htable_lookup(cpu, c.last_tb.pc, c.last_tb.cs_base,
                                   c.last_tb.flags, c.cf_mask);
        if (last_tb) {
          tb_add_jump(last_tb, c.tb_exit, tb);
        }
      }
    }

  }

  close(fd);

}

/* A simplified persistent mode handler, used as explained in README.llvm. */

void weizz_persistent_loop() {

  static unsigned char first_pass = 1;
  static unsigned int cycle_cnt;
  static struct weizz_tsl exit_cmd_tsl = {{-1, 0, 0, 0}, NULL};

  if (!weizz_fork_child) return;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(light_map, 0, MAP_SIZE);
      if (is_heavy)
        memset(heavy_map, 0, MAP_SIZE);

      light_map[0] = 1;
      prev_loc = 0;

    }

    cycle_cnt = weizz_persistent_cnt;
    first_pass = 0;
    persistent_stack_offset = TARGET_LONG_BITS / 8;

    return;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      if (write(TSL_FD, &exit_cmd_tsl, sizeof(struct weizz_tsl)) !=
          sizeof(struct weizz_tsl)) {

        /* Exit the persistent loop on pipe error */
        exit(0);

      }

      raise(SIGSTOP);

      light_map[0] = 1;
      prev_loc = 0;

    } else {

      exit(0);

    }

  }

}

static void weizz_initialize(CPUState *cpu)
{
    if(getenv("WEIZZ_DISABLE_PATCH"))
      enable_cmp_patching = 0;
    else
      enable_cmp_patching = 1;

    if (getenv("WEIZZ_INST_LIBS")) {

      weizz_start_code = 0;
      weizz_end_code   = (abi_ulong)-1;
    }
    
    ctx_sensitive = getenv("WEIZZ_CTX_SENSITIVE") != NULL;
    
    char* target_lib_name = getenv("WEIZZ_TARGET_LIB");
    if (target_lib_name) {
    
        procmaps_iterator* maps = pmparser_parse(-1);
        procmaps_struct* maps_tmp = NULL;
	      
	      while ((maps_tmp = pmparser_next(maps)) != NULL) {
		        if (strstr(maps_tmp->pathname, target_lib_name) != NULL) {
		            if (maps_tmp->is_x) {
		                if (!weizz_start_tgt_lib_code)
		                    weizz_start_tgt_lib_code = (target_ulong)maps_tmp->addr_start;
                    if (!weizz_end_tgt_lib_code)
		                    weizz_end_tgt_lib_code = (target_ulong)maps_tmp->addr_end;
		            }
		            if (!weizz_tgt_lib_start)
                    weizz_tgt_lib_start = (target_ulong)maps_tmp->addr_start;
                if (!weizz_tgt_lib_end)
                    weizz_tgt_lib_end = (target_ulong)maps_tmp->addr_end;
		        }
	      }

	      pmparser_free(maps);
    }

    char* inst_r = getenv("WEIZZ_INST_RATIO");

    if (inst_r) {

      unsigned int r;

      r = atoi(inst_r);

      if (r > 100) r = 100;
      if (!r) r = 1;

      weizz_inst_rms = MAP_SIZE * r / 100;

    }

    //fprintf(stderr, "weizz_tgt_lib_start: %p\nweizz_tgt_lib_end: %p\n\n", weizz_tgt_lib_start, weizz_tgt_lib_end);

    if (getenv("WEIZZ_IGNORE_INST")) {
        is_heavy = 1;
        heavy_map = calloc(1, sizeof(struct cmp_map));
        light_map = calloc(1, MAP_SIZE);
        
        if (enable_cmp_patching) {
          cmp_patch_map = calloc(1, WMAP_WIDTH);
          if (getenv("WEIZZ_PATCH_MAP")) {
            
            int fd = open(getenv("WEIZZ_PATCH_MAP"), O_RDONLY);

            if (fd < 0)
              exit(-9);

            read(fd, cmp_patch_map, WMAP_WIDTH);
            close(fd);
          }
        }
        return;
    }
    
    char *id_str = getenv(LIGHT_SHM_ENV_VAR);
    if(!id_str)
      id_str = getenv("__AFL_SHM_ID");
    if(!id_str)
        exit(1);
    
    int shm_id = atoi(id_str);
    light_map = (uint8_t*)shmat(shm_id, NULL, 0);

    if (light_map == (uint8_t*)-1)
        exit(1);

    if (getenv("__WEIZZ_HEAVY__")) {
      is_heavy = 1;
      id_str = getenv(HEAVY_SHM_ENV_VAR);
      if(!id_str)
          exit(1);
      
      shm_id = atoi(id_str);
      heavy_map = (uint8_t*)shmat(shm_id, NULL, 0);

      if (heavy_map == (uint8_t*)-1)
          exit(1);
    }

    if (enable_cmp_patching) {
    
      id_str = getenv(PATCH_SHM_ENV_VAR);
      if(!id_str)
          exit(1);
      
      shm_id = atoi(id_str);
      cmp_patch_map = (uint8_t*)shmat(shm_id, NULL, 0);

      if (cmp_patch_map == (uint8_t*)-1)
          exit(1);
    }

    /* AFL disables it so we follow the master */
    rcu_disable_atfork();
    
    is_persistent = getenv("WEIZZ_QEMU_PERSISTENT_ADDR") != NULL;

    if (is_persistent) {
        weizz_persistent_addr = strtoll(getenv("WEIZZ_QEMU_PERSISTENT_ADDR"), NULL, 16);
        if (getenv("WEIZZL_QEMU_PERSISTENT_RET"))
          weizz_persistent_ret_addr =
              strtoll(getenv("WEIZZ_QEMU_PERSISTENT_RET"), NULL, 16);
    }

    if (getenv("WEIZZ_QEMU_PERSISTENT_CNT"))
      weizz_persistent_cnt = strtoll(getenv("WEIZZ_QEMU_PERSISTENT_CNT"), NULL, 16);
    else
      weizz_persistent_cnt = PERSISTENT_DEFAULT_MAX_CNT;
    
    /* forkserver */
    static uint32_t tmp;

    /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

    pid_t child_pid;
    int   t_fd[2];
    char    child_stopped = 0;

    if (write(FORKSRV_FD + 1, &tmp, 4) != 4) return;

    weizz_forksrv_pid = getpid();

    /* All right, let's await orders... */

    while (1) {
        int status;
        unsigned int was_killed;

        /* Whoops, parent dead? */
        if (read(FORKSRV_FD, &tmp, 4) != 4) exit(2);

        weizz_target_cmp = tmp;

        if (child_stopped && was_killed) {
            child_stopped = 0;
            if (waitpid(child_pid, &status, 0) < 0) exit(8);
        }

        if (!child_stopped) {
            /* Establish a channel with child to grab translation commands. We'll
               read from t_fd[0], child will write to TSL_FD. */
            if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
            close(t_fd[1]);

            child_pid = fork();
            if (child_pid < 0) exit(4);

            if (!child_pid) {
                /* Child process. Close descriptors and run free. */
                weizz_fork_child = 1;
                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                close(t_fd[0]);
                return;
            }

            /* Parent. */
            close(TSL_FD);
        } else {
          /* Special handling for persistent mode: if the child is alive but
             currently stopped, simply restart it with SIGCONT. */
          kill(child_pid, SIGCONT);
          child_stopped = 0;
        }

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

        /* Collect translation requests until child dies and closes the pipe. */
        weizz_wait_tsl(cpu, t_fd[0]);

        /* Get and relay exit status to parent. */
        if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) exit(6);
        
        if (WIFSTOPPED(status)) child_stopped = 1;
        
        if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);
    }
}

/* weizz */

/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

#if !defined(CONFIG_USER_ONLY)
/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100

static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
    int64_t cpu_icount;

    if (!icount_align_option) {
        return;
    }

    cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    sc->diff_clk += cpu_icount_to_ns(sc->last_cpu_icount - cpu_icount);
    sc->last_cpu_icount = cpu_icount;

    if (sc->diff_clk > VM_CLOCK_ADVANCE) {
#ifndef _WIN32
        struct timespec sleep_delay, rem_delay;
        sleep_delay.tv_sec = sc->diff_clk / 1000000000LL;
        sleep_delay.tv_nsec = sc->diff_clk % 1000000000LL;
        if (nanosleep(&sleep_delay, &rem_delay) < 0) {
            sc->diff_clk = rem_delay.tv_sec * 1000000000LL + rem_delay.tv_nsec;
        } else {
            sc->diff_clk = 0;
        }
#else
        Sleep(sc->diff_clk / SCALE_MS);
        sc->diff_clk = 0;
#endif
    }
}

static void print_delay(const SyncClocks *sc)
{
    static float threshold_delay;
    static int64_t last_realtime_clock;
    static int nb_prints;

    if (icount_align_option &&
        sc->realtime_clock - last_realtime_clock >= MAX_DELAY_PRINT_RATE &&
        nb_prints < MAX_NB_PRINTS) {
        if ((-sc->diff_clk / (float)1000000000LL > threshold_delay) ||
            (-sc->diff_clk / (float)1000000000LL <
             (threshold_delay - THRESHOLD_REDUCE))) {
            threshold_delay = (-sc->diff_clk / 1000000000LL) + 1;
            printf("Warning: The guest is now late by %.1f to %.1f seconds\n",
                   threshold_delay - 1,
                   threshold_delay);
            nb_prints++;
            last_realtime_clock = sc->realtime_clock;
        }
    }
}

static void init_delay_params(SyncClocks *sc,
                              const CPUState *cpu)
{
    if (!icount_align_option) {
        return;
    }
    sc->realtime_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    sc->diff_clk = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - sc->realtime_clock;
    sc->last_cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    if (sc->diff_clk < max_delay) {
        max_delay = sc->diff_clk;
    }
    if (sc->diff_clk > max_advance) {
        max_advance = sc->diff_clk;
    }

    /* Print every 2s max if the guest is late. We limit the number
       of printed messages to NB_PRINT_MAX(currently 100) */
    print_delay(sc);
}
#else
static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
}

static void init_delay_params(SyncClocks *sc, const CPUState *cpu)
{
}
#endif /* CONFIG USER ONLY */

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc.ptr;

    /* weizz */
    
    if(itb->pc == weizz_entry_point) {
        weizz_initialize(cpu);
    }
    
    /* weizz */

    qemu_log_mask_and_addr(CPU_LOG_EXEC, itb->pc,
                           "Trace %d: %p ["
                           TARGET_FMT_lx "/" TARGET_FMT_lx "/%#x] %s\n",
                           cpu->cpu_index, itb->tc.ptr,
                           itb->cs_base, itb->pc, itb->flags,
                           lookup_symbol(itb->pc));

#if defined(DEBUG_DISAS)
    if (qemu_loglevel_mask(CPU_LOG_TB_CPU)
        && qemu_log_in_addr_range(itb->pc)) {
        qemu_log_lock();
        int flags = 0;
        if (qemu_loglevel_mask(CPU_LOG_TB_FPU)) {
            flags |= CPU_DUMP_FPU;
        }
#if defined(TARGET_I386)
        flags |= CPU_DUMP_CCOP;
#endif
        log_cpu_state(cpu, flags);
        qemu_log_unlock();
    }
#endif /* DEBUG_DISAS */

    cpu->can_do_io = !use_icount;
    ret = tcg_qemu_tb_exec(env, tb_ptr);
    cpu->can_do_io = 1;
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    tb_exit = ret & TB_EXIT_MASK;
    trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        qemu_log_mask_and_addr(CPU_LOG_EXEC, last_tb->pc,
                               "Stopped execution of TB chain before %p ["
                               TARGET_FMT_lx "] %s\n",
                               last_tb->tc.ptr, last_tb->pc,
                               lookup_symbol(last_tb->pc));
        if (cc->synchronize_from_tb) {
            cc->synchronize_from_tb(cpu, last_tb);
        } else {
            assert(cc->set_pc);
            cc->set_pc(cpu, last_tb->pc);
        }
    }
    return ret;
}

#ifndef CONFIG_USER_ONLY
/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *cpu, int max_cycles,
                             TranslationBlock *orig_tb, bool ignore_icount)
{
    TranslationBlock *tb;
    uint32_t cflags = curr_cflags() | CF_NOCACHE;

    if (ignore_icount) {
        cflags &= ~CF_USE_ICOUNT;
    }

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    cflags |= MIN(max_cycles, CF_COUNT_MASK);

    mmap_lock();
    tb = tb_gen_code(cpu, orig_tb->pc, orig_tb->cs_base,
                     orig_tb->flags, cflags);
    tb->orig_tb = orig_tb;
    mmap_unlock();

    /* execute the generated code */
    trace_exec_tb_nocache(tb, tb->pc);
    cpu_tb_exec(cpu, tb);

    mmap_lock();
    tb_phys_invalidate(tb, -1);
    mmap_unlock();
    tcg_tb_remove(tb);
}
#endif

void cpu_exec_step_atomic(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;
    uint32_t cflags = 1;
    uint32_t cf_mask = cflags & CF_HASH_MASK;
    /* volatile because we modify it between setjmp and longjmp */
    volatile bool in_exclusive_region = false;

    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
        tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, cf_mask);
        if (tb == NULL) {
            mmap_lock();
            tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
            mmap_unlock();
        }

        start_exclusive();

        /* Since we got here, we know that parallel_cpus must be true.  */
        parallel_cpus = false;
        in_exclusive_region = true;
        cc->cpu_exec_enter(cpu);
        /* execute the generated code */
        trace_exec_tb(tb, pc);
        cpu_tb_exec(cpu, tb);
        cc->cpu_exec_exit(cpu);
    } else {
        /*
         * The mmap_lock is dropped by tb_gen_code if it runs out of
         * memory.
         */
#ifndef CONFIG_SOFTMMU
        tcg_debug_assert(!have_mmap_lock());
#endif
        assert_no_pages_locked();
    }

    if (in_exclusive_region) {
        /* We might longjump out of either the codegen or the
         * execution, so must make sure we only end the exclusive
         * region if we started it.
         */
        parallel_cpus = true;
        end_exclusive();
    }
}

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t phys_page1;
    uint32_t flags;
    uint32_t cf_mask;
    uint32_t trace_vcpu_dstate;
};

static bool tb_lookup_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if (tb->pc == desc->pc &&
        tb->page_addr[0] == desc->phys_page1 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags &&
        tb->trace_vcpu_dstate == desc->trace_vcpu_dstate &&
        (tb_cflags(tb) & (CF_HASH_MASK | CF_INVALID)) == desc->cf_mask) {
        /* check next page if needed */
        if (tb->page_addr[1] == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page2;
            target_ulong virt_page2;

            virt_page2 = (desc->pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
            phys_page2 = get_page_addr_code(desc->env, virt_page2);
            if (tb->page_addr[1] == phys_page2) {
                return true;
            }
        }
    }
    return false;
}

TranslationBlock *tb_htable_lookup(CPUState *cpu, target_ulong pc,
                                   target_ulong cs_base, uint32_t flags,
                                   uint32_t cf_mask)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = (CPUArchState *)cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.cf_mask = cf_mask;
    desc.trace_vcpu_dstate = *cpu->trace_dstate;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
    if (phys_pc == -1) {
        return NULL;
    }
    desc.phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_hash_func(phys_pc, pc, flags, cf_mask, *cpu->trace_dstate);
    return qht_lookup_custom(&tb_ctx.htable, &desc, h, tb_lookup_cmp);
}

void tb_set_jmp_target(TranslationBlock *tb, int n, uintptr_t addr)
{
    if (TCG_TARGET_HAS_direct_jump) {
        uintptr_t offset = tb->jmp_target_arg[n];
        uintptr_t tc_ptr = (uintptr_t)tb->tc.ptr;
        tb_target_set_jmp_target(tc_ptr, tc_ptr + offset, addr);
    } else {
        tb->jmp_target_arg[n] = addr;
    }
}

static inline void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next)
{
    uintptr_t old;

    assert(n < ARRAY_SIZE(tb->jmp_list_next));
    qemu_spin_lock(&tb_next->jmp_lock);

    /* make sure the destination TB is valid */
    if (tb_next->cflags & CF_INVALID) {
        goto out_unlock_next;
    }
    /* Atomically claim the jump destination slot only if it was NULL */
    old = atomic_cmpxchg(&tb->jmp_dest[n], (uintptr_t)NULL, (uintptr_t)tb_next);
    if (old) {
        goto out_unlock_next;
    }

    /* patch the native jump address */
    tb_set_jmp_target(tb, n, (uintptr_t)tb_next->tc.ptr);

    /* add in TB jmp list */
    tb->jmp_list_next[n] = tb_next->jmp_list_head;
    tb_next->jmp_list_head = (uintptr_t)tb | n;

    qemu_spin_unlock(&tb_next->jmp_lock);

    qemu_log_mask_and_addr(CPU_LOG_EXEC, tb->pc,
                           "Linking TBs %p [" TARGET_FMT_lx
                           "] index %d -> %p [" TARGET_FMT_lx "]\n",
                           tb->tc.ptr, tb->pc, n,
                           tb_next->tc.ptr, tb_next->pc);
    return;

 out_unlock_next:
    qemu_spin_unlock(&tb_next->jmp_lock);
    return;
}

static inline TranslationBlock *tb_find(CPUState *cpu,
                                        TranslationBlock *last_tb,
                                        int tb_exit, uint32_t cf_mask)
{
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;
    bool was_translated = false, was_chained = false;

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, cf_mask);
    if (tb == NULL) {
        mmap_lock();
        tb = tb_gen_code(cpu, pc, cs_base, flags, cf_mask);
        was_translated = true;
        mmap_unlock();
        /* We add the TB in the virtual pc hash table for the fast lookup */
        atomic_set(&cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)], tb);
    }
#ifndef CONFIG_USER_ONLY
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        last_tb = NULL;
    }
#endif
    /* See if we can patch the calling TB. */
    if (last_tb) {
        tb_add_jump(last_tb, tb_exit, tb);
        was_chained = true;
    }
    if (was_translated || was_chained) {
        weizz_request_tsl(pc, cs_base, flags, cf_mask, was_chained ? last_tb : NULL, tb_exit);
     }
    return tb;
}

static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
        if ((cpu->interrupt_request & CPU_INTERRUPT_POLL)
            && replay_interrupt()) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            qemu_mutex_lock_iothread();
            apic_poll_irq(x86_cpu->apic_state);
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_POLL);
            qemu_mutex_unlock_iothread();
        }
#endif
        if (!cpu_has_work(cpu)) {
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    if (cpu->exception_index < 0) {
#ifndef CONFIG_USER_ONLY
        if (replay_has_exception()
               && cpu->icount_decr.u16.low + cpu->icount_extra == 0) {
            /* try to cause an exception pending in the log */
            cpu_exec_nocache(cpu, 1, tb_find(cpu, NULL, 0, curr_cflags()), true);
        }
#endif
        if (cpu->exception_index < 0) {
            return false;
        }
    }

    if (cpu->exception_index >= EXCP_INTERRUPT) {
        /* exit request from the cpu execution loop */
        *ret = cpu->exception_index;
        if (*ret == EXCP_DEBUG) {
            cpu_handle_debug_exception(cpu);
        }
        cpu->exception_index = -1;
        return true;
    } else {
#if defined(CONFIG_USER_ONLY)
        /* if user mode only, we simulate a fake exception
           which will be handled outside the cpu execution
           loop */
#if defined(TARGET_I386)
        CPUClass *cc = CPU_GET_CLASS(cpu);
        cc->do_interrupt(cpu);
#endif
        *ret = cpu->exception_index;
        cpu->exception_index = -1;
        return true;
#else
        if (replay_exception()) {
            CPUClass *cc = CPU_GET_CLASS(cpu);
            qemu_mutex_lock_iothread();
            cc->do_interrupt(cpu);
            qemu_mutex_unlock_iothread();
            cpu->exception_index = -1;
        } else if (!replay_has_interrupt()) {
            /* give a chance to iothread in replay mode */
            *ret = EXCP_INTERRUPT;
            return true;
        }
#endif
    }

    return false;
}

static inline bool cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    /* Clear the interrupt flag now since we're processing
     * cpu->interrupt_request and cpu->exit_request.
     * Ensure zeroing happens before reading cpu->exit_request or
     * cpu->interrupt_request (see also smp_wmb in cpu_exit())
     */
    atomic_mb_set(&cpu->icount_decr.u16.high, 0);

    if (unlikely(atomic_read(&cpu->interrupt_request))) {
        int interrupt_request;
        qemu_mutex_lock_iothread();
        interrupt_request = cpu->interrupt_request;
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            qemu_mutex_unlock_iothread();
            return true;
        }
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        } else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            qemu_mutex_unlock_iothread();
            return true;
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            qemu_mutex_unlock_iothread();
            return true;
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            qemu_mutex_unlock_iothread();
            return true;
        }
#endif
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                replay_interrupt();
                cpu->exception_index = -1;
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }

        /* If we exit via cpu_loop_exit/longjmp it is reset in cpu_exec */
        qemu_mutex_unlock_iothread();
    }

    /* Finally, check if we need to exit to the main loop.  */
    if (unlikely(atomic_read(&cpu->exit_request)
        || (use_icount && cpu->icount_decr.u16.low + cpu->icount_extra == 0))) {
        atomic_set(&cpu->exit_request, 0);
        if (cpu->exception_index == -1) {
            cpu->exception_index = EXCP_INTERRUPT;
        }
        return true;
    }

    return false;
}

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit)
{
    uintptr_t ret;
    int32_t insns_left;

    trace_exec_tb(tb, tb->pc);
    ret = cpu_tb_exec(cpu, tb);
    tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    *tb_exit = ret & TB_EXIT_MASK;
    if (*tb_exit != TB_EXIT_REQUESTED) {
        *last_tb = tb;
        return;
    }

    *last_tb = NULL;
    insns_left = atomic_read(&cpu->icount_decr.u32);
    if (insns_left < 0) {
        /* Something asked us to stop executing chained TBs; just
         * continue round the main loop. Whatever requested the exit
         * will also have set something else (eg exit_request or
         * interrupt_request) which will be handled by
         * cpu_handle_interrupt.  cpu_handle_interrupt will also
         * clear cpu->icount_decr.u16.high.
         */
        return;
    }

    /* Instruction counter expired.  */
    assert(use_icount);
#ifndef CONFIG_USER_ONLY
    /* Ensure global icount has gone forward */
    cpu_update_icount(cpu);
    /* Refill decrementer and continue execution.  */
    insns_left = MIN(0xffff, cpu->icount_budget);
    cpu->icount_decr.u16.low = insns_left;
    cpu->icount_extra = cpu->icount_budget - insns_left;
    if (!cpu->icount_extra) {
        /* Execute any remaining instructions, then let the main loop
         * handle the next event.
         */
        if (insns_left > 0) {
            cpu_exec_nocache(cpu, insns_left, tb, false);
        }
    }
#endif
}

/* main execution loop */

int cpu_exec(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc = { 0 };

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    rcu_read_lock();

    cc->cpu_exec_enter(cpu);

    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);

    /* prepare setjmp context for exception handling */
    if (sigsetjmp(cpu->jmp_env, 0) != 0) {
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
        /* Some compilers wrongly smash all local variables after
         * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
         * Reload essential local variables here for those compilers.
         * Newer versions of gcc would complain about this code (-Wclobbered). */
        cpu = current_cpu;
        cc = CPU_GET_CLASS(cpu);
#else /* buggy compiler */
        /* Assert that the compiler does not smash local variables. */
        g_assert(cpu == current_cpu);
        g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */
#ifndef CONFIG_SOFTMMU
        tcg_debug_assert(!have_mmap_lock());
#endif
        if (qemu_mutex_iothread_locked()) {
            qemu_mutex_unlock_iothread();
        }
    }

    /* if an exception is pending, we execute it here */
    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;

        while (!cpu_handle_interrupt(cpu, &last_tb)) {
            uint32_t cflags = cpu->cflags_next_tb;
            TranslationBlock *tb;

            /* When requested, use an exact setting for cflags for the next
               execution.  This is used for icount, precise smc, and stop-
               after-access watchpoints.  Since this request should never
               have CF_INVALID set, -1 is a convenient invalid value that
               does not require tcg headers for cpu_common_reset.  */
            if (cflags == -1) {
                cflags = curr_cflags();
            } else {
                cpu->cflags_next_tb = -1;
            }

            tb = tb_find(cpu, last_tb, tb_exit, cflags);
            cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
            /* Try to align the host and virtual clocks
               if the guest is in advance */
            align_clocks(&sc, cpu);
        }
    }

    cc->cpu_exec_exit(cpu);
    rcu_read_unlock();

    return ret;
}
