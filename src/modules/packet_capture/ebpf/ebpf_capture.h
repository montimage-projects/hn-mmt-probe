/*
 * ebpf_capture.h
 *
 * Public API for the AF_XDP / eBPF packet capture backend.
 * Drop-in replacement for pcap_capture.h / dpdk_capture.h.
 *
 * Enable at build time with: make EBPF_CAPTURE compile
 */

#ifndef SRC_MODULES_EBPF_EBPF_CAPTURE_H_
#define SRC_MODULES_EBPF_EBPF_CAPTURE_H_

#include "../../../context.h"

/**
 * Initialise AF_XDP capture on the interface named in context->config->input,
 * start worker threads (SMP) or run inline (single-thread), then block in
 * the packet-receive loop until context->is_exiting is set.
 * Cleans up all resources before returning.
 *
 * Restrictions:
 *   - Online (live interface) mode only; offline PCAP-file analysis is not
 *     supported.  Use PCAP mode (-t / input.mode = OFFLINE) for that.
 *   - Requires Linux >= 4.18 and libbpf >= 0.2.
 *   - Requires root or CAP_NET_ADMIN + CAP_BPF.
 */
void ebpf_capture_start( probe_context_t *context );

/**
 * Signal the capture loop to stop.
 * Safe to call from a signal handler.  The loop drains within
 * POLL_TIMEOUT_MS (100 ms) of this call.
 */
void ebpf_capture_stop( probe_context_t *context );

/**
 * Release all eBPF/AF_XDP resources.
 * Called automatically by ebpf_capture_start() on exit; exposed here for
 * symmetry with the PCAP module and for error-path cleanup by callers.
 */
void ebpf_capture_release( probe_context_t *context );

#endif /* SRC_MODULES_EBPF_EBPF_CAPTURE_H_ */
