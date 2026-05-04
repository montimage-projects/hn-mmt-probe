
## Architecture

The eBPF backend mirrors the PCAP module architecture exactly:

```
Main thread (reader)
  └── AF_XDP socket on queue 0
        │
        ├── SMP mode  : hash packet → per-worker SPSC ring → N worker threads
        │                            (same lock-free ring reused from pcap/)
        └── 1-thread  : call worker_process_a_packet() inline
```

The rest of the probe (DPI engine, outputs, security, dynamic config) is completely unchanged.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Mirrors PCAP architecture | Same SPSC ring, same worker dispatch, same start/stop API — zero learning curve, easy to review |
| `libbpf_flags = 0` (auto-load XDP programme) | No `clang` build-time dependency; libbpf's built-in programme is functionally identical to the reference `kern/xdp_kern.c` |
| `XDP_FLAGS_SKB_MODE` + `XDP_COPY` | Works on every NIC without driver XDP support; upgrade path to native mode / zero-copy is a one-line flag change |
| Single queue 0 | Matches PCAP model; multi-queue requires environment-specific NIC configuration |
| Reuses `pcap/data_spsc_ring.c` | No code duplication; two extra `MODULE_SRCS` lines instead of copying 200+ lines |
| Online-only, clear error for offline mode | AF_XDP is inherently live-interface; users get a clear message to use PCAP mode for `.pcap` files |
| `ebpf_capture_stop()` is a no-op | The main loop polls with 100 ms timeout and checks `ctx->is_exiting`; the signal handler already sets the flag |

---

## Requirements

| Requirement | Minimum version |
|-------------|----------------|
| Linux kernel | 4.18 (AF_XDP support) |
| libbpf | 0.2 |
| Capabilities | `CAP_NET_ADMIN` + `CAP_BPF` (kernel ≥ 5.8), or root |

---

## Upgrade Path

| Feature | How to enable |
|---------|--------------|
| Native XDP (faster, NIC-driver dependent) | Change `XDP_FLAGS_SKB_MODE` → `XDP_FLAGS_DRV_MODE` in `ebpf_capture.c` |
| Zero-copy UMEM | Change `XDP_COPY` → `XDP_ZEROCOPY` in `ebpf_capture.c` (requires driver support) |
| Custom XDP kernel programme | Compile `kern/xdp_kern.c` with clang, load explicitly, set `XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD` |
| Multi-queue (one socket per worker) | Create one `xsk_socket_info` per worker thread, each bound to a different queue id |