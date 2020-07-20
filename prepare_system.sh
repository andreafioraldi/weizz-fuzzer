#!/bin/bash
# from AFLplusplus https://github.com/vanhauser-thc/AFLplusplus
echo "This reconfigures the system to enable weizz and also have a better fuzzing performance"
if [[ $EUID -ne 0 ]] || ! [ `id -u` = 0 ]; then
	echo if you are root \(which you are currently not\)
	exit 1
fi
sysctl -w kernel.shmmax=2694840320
sysctl -w kernel.core_pattern=core
sysctl -w kernel.randomize_va_space=0
sysctl -w kernel.sched_child_runs_first=1
sysctl -w kernel.sched_autogroup_enabled=1
sysctl -w kernel.sched_migration_cost_ns=50000000
sysctl -w kernel.sched_latency_ns=250000000
echo never > /sys/kernel/mm/transparent_hugepage/enabled
test -e /sys/devices/system/cpu/cpufreq/scaling_governor && echo performance | tee /sys/devices/system/cpu/cpufreq/scaling_governor
test -e /sys/devices/system/cpu/cpufreq/policy0/scaling_governor && echo performance | tee /sys/devices/system/cpu/cpufreq/policy*/scaling_governor
test -e /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor && echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
test -e /sys/devices/system/cpu/intel_pstate/no_turbo && echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo
test -e /sys/devices/system/cpu/cpufreq/boost && echo 1 > /sys/devices/system/cpu/cpufreq/boost
