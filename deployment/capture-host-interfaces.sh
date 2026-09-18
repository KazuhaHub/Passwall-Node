#!/bin/sh
# Captures the kernel interfaces the host collector parses.
#
# WHY THIS EXISTS. The unit tests in internal/host run against fixtures, and a
# fixture can only ever encode what its author BELIEVED a kernel writes. Running
# the collector against a real host is the only thing that can contradict that,
# and when it does, the disagreement is usually a format detail — a padding
# column, a field a given kernel omits, a table that is empty for a legitimate
# reason. This dumps exactly the files the collector reads so the two can be held
# side by side.
#
# It is also the right thing to ask for when a collector misbehaves on someone
# else's machine: the output names no secrets and describes no workload.
#
# READ-ONLY. It writes nothing outside its own output directory.
#
# Usage: deployment/capture-host-interfaces.sh [output-directory]

set -eu

out=${1:-/tmp/host-capture}
rm -rf "$out"
mkdir -p "$out"

# Record a file, or record that it is ABSENT. Which files are missing is as
# informative as which are present — several collector behaviours are about a
# kernel that does not expose something.
take() {
    src=$1
    dest="$out/$2"
    mkdir -p "$(dirname "$dest")"
    if [ -r "$src" ]; then
        cat "$src" >"$dest" 2>/dev/null || echo "(unreadable)" >"$dest"
    else
        echo "(absent)" >"$dest"
    fi
}

take /etc/os-release                                      etc/os-release
take /proc/uptime                                         proc/uptime
take /proc/loadavg                                        proc/loadavg
take /proc/stat                                           proc/stat
take /proc/meminfo                                        proc/meminfo
take /proc/self/stat                                      proc/self/stat
take /proc/self/limits                                    proc/self/limits
take /proc/self/cgroup                                    proc/self/cgroup
take /proc/1/comm                                         proc/1_comm
take /proc/1/cgroup                                       proc/1_cgroup
take /proc/self/mountinfo                                 proc/self/mountinfo
take /proc/sys/kernel/random/boot_id                      proc/sys_kernel_random_boot_id
take /proc/sys/kernel/osrelease                           proc/sys_kernel_osrelease
take /proc/net/dev                                        proc/net/dev
take /proc/net/snmp                                       proc/net/snmp
take /proc/net/sockstat                                   proc/net/sockstat
take /proc/net/route                                      proc/net/route
take /proc/net/ipv6_route                                 proc/net/ipv6_route
take /proc/sys/net/ipv4/tcp_available_congestion_control  proc/sys_net_ipv4_cc_available
take /proc/sys/net/ipv4/tcp_congestion_control            proc/sys_net_ipv4_cc_default
take /proc/sys/net/core/default_qdisc                     proc/sys_net_core_default_qdisc
take /proc/sys/net/netfilter/nf_conntrack_count           proc/nf_conntrack_count
take /proc/sys/net/netfilter/nf_conntrack_max             proc/nf_conntrack_max

# The cgroup files live under the agent's OWN cgroup, not at the hierarchy root,
# so they are read through whatever /proc/self/cgroup names.
cgroup_path=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null | head -1)
if [ -n "${cgroup_path:-}" ]; then
    root="/sys/fs/cgroup${cgroup_path%/}"
    for file in cpu.max cpu.stat cpuset.cpus.effective memory.current memory.max \
        memory.swap.current memory.swap.max memory.events; do
        take "$root/$file" "sys/fs_cgroup/$file"
    done
fi
take /sys/fs/cgroup/cgroup.controllers sys/fs_cgroup/cgroup.controllers

# Per-interface metadata, for every interface the counter table lists.
for iface in $(ls /sys/class/net 2>/dev/null); do
    take "/sys/class/net/$iface/flags"     "sys/class_net/$iface/flags"
    take "/sys/class/net/$iface/ifindex"   "sys/class_net/$iface/ifindex"
    take "/sys/class/net/$iface/mtu"       "sys/class_net/$iface/mtu"
    take "/sys/class/net/$iface/operstate" "sys/class_net/$iface/operstate"
    take "/sys/class/net/$iface/speed"     "sys/class_net/$iface/speed"
done

# auxv is binary, so only the size is recorded — what the collector depends on is
# whether AT_CLKTCK is in there, which its own live test reports directly.
if [ -r /proc/self/auxv ]; then
    wc -c </proc/self/auxv >"$out/proc/auxv_size"
else
    echo "(absent)" >"$out/proc/auxv_size"
fi

{
    echo "kernel:     $(uname -r)"
    echo "arch:       $(uname -m)"
    echo "os:         $(. /etc/os-release 2>/dev/null && echo "${ID:-?} ${VERSION_ID:-?}")"
    echo "cgroupfs:   $(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)"
    echo "cgroup path:${cgroup_path:- unknown}"
    echo "interfaces: $(ls /sys/class/net 2>/dev/null | tr '\n' ' ')"
    echo "uid:        $(id -u)"
    echo "in container: $([ -e /.dockerenv ] && echo yes || echo 'unknown — see the root fstype below')"
    # The filesystem type is the field after the "-" separator, not the last one:
    # the tail is the superblock options, which reads as a plausible answer and
    # is not the answer.
    echo "root fstype: $(awk '$5 == "/" { for (i = 1; i <= NF; i++) if ($i == "-") { print $(i + 1); exit } }' /proc/self/mountinfo 2>/dev/null)"
} >"$out/summary.txt"

echo "captured to $out"
cat "$out/summary.txt"
