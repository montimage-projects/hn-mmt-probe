/* SPDX-License-Identifier: GPL-2.0
 *
 * xdp_kern.c — XDP kernel program for MMT-Probe AF_XDP capture.
 *
 * This file is provided as a REFERENCE / CUSTOMISATION POINT only.
 * It has no actual effect on MMT-Probe.
 *
 * By default, MMT-Probe lets libbpf auto-load its own equivalent built-in
 * program.  If you want to replace that with a customised version (e.g. to
 * add kernel-side filtering), compile this file with clang and pass the
 * resulting object path to ebpf_capture_start() via the config.
 *
 * Compile (requires clang + linux-headers + libbpf-dev):
 *   clang -O2 -Wall -target bpf \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c xdp_kern.c -o xdp_kern.o
 *
 * Logic: for each incoming packet, check whether an AF_XDP socket is
 * registered for the packet's RX queue in the XSKMAP.  If so, redirect
 * the packet to that socket; otherwise let the packet continue through
 * the normal kernel network stack (XDP_PASS).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Map updated by userspace: queue_index → AF_XDP socket fd */
struct {
	__uint(type,       BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);               /* supports up to 64 RX queues */
	__type(key,        __u32);
	__type(value,      __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	__u32 index = ctx->rx_queue_index;

	/*
	 * bpf_map_lookup_elem returns non-NULL when a socket is registered
	 * for this queue.  bpf_redirect_map then steers the packet there.
	 * A second argument of 0 means "drop if the target queue is full"
	 * (use XDP_PASS as second arg to fall-back to the kernel stack instead).
	 */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
