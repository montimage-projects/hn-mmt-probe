/*
 * ebpf_capture.c
 *
 * AF_XDP / eBPF packet capture backend for MMT-Probe.
 *
 * Architecture mirrors pcap_capture.c:
 *   - One AF_XDP socket on NIC queue 0 (SKB/copy mode — works on any NIC).
 *   - SMP mode  : main thread reads a batch, dispatches to per-worker SPSC
 *                 rings (same lock-free ring reused from the PCAP module).
 *   - 1-thread  : main thread reads and calls worker_process_a_packet()
 *                 inline, no extra ring overhead.
 *
 * libbpf automatically loads a built-in XDP redirect programme the first
 * time xsk_socket__create() is called (libbpf_flags = 0).  For a
 * customised XDP programme see kern/xdp_kern.c.
 *
 * Requirements
 *   Kernel  : Linux >= 4.18 (AF_XDP sockets)
 *   Library : libbpf >= 0.2  (package libbpf-dev)
 *   Caps    : CAP_NET_ADMIN + CAP_BPF  (or root)
 *
 * Build
 *   make EBPF_CAPTURE compile
 */

#ifndef EBPF_MODULE
#define EBPF_MODULE
#endif

#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <net/if.h>
#include <poll.h>
#include <errno.h>
#include <string.h>

#include <bpf/libbpf.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>

#include "../../../lib/log.h"
#include "../../../lib/malloc.h"
#include "../../../lib/ms_timer.h"
#include "../../../lib/system_info.h"
#include "../../../worker.h"
/* Reuse the PCAP module's lock-free SPSC ring for worker-thread dispatch */
#include "../pcap/data_spsc_ring.h"

#include "ebpf_capture.h"

/* ── Tuneable constants ──────────────────────────────────────────────────── */

/* Number of UMEM slots — must be a power of 2.
 * Each slot is XSK_UMEM__DEFAULT_FRAME_SIZE (4096) bytes.
 * Total UMEM = 4096 * 4096 = 16 MB. */
#define XSK_NUM_FRAMES     4096u

/* Packets drained per poll() wakeup */
#define XSK_RX_BATCH       64u

/* poll() timeout in ms — controls maximum latency from ebpf_capture_stop()
 * to the receive loop actually exiting. */
#define POLL_TIMEOUT_MS    100

/* Sentinel value: a pkthdr.len of 0 tells a worker thread to exit. */
#define BREAK_EBPF_NUMBER  0u

/* ── Internal structures ─────────────────────────────────────────────────── */

/* AF_XDP socket together with its UMEM */
struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;   /* TX completion — unused for RX-only */
    struct xsk_umem     *umem;
    struct xsk_socket   *xsk;
    void                *umem_area;
    size_t               umem_size;
};

/* Per-worker eBPF context — one per SMP worker thread */
struct ebpf_worker_context_struct {
    pthread_t        thread_handler;
    data_spsc_ring_t fifo;            /* SPSC ring fed by the reader (main thread) */
};

/* Per-probe eBPF context — one instance, owned by probe_context_t.modules */
struct ebpf_probe_context_struct {
    struct xsk_socket_info *xsk_info;
};

/* ── Flow-hash (symmetric, mirrors pcap_capture.c) ──────────────────────── */

static inline uint32_t _hash32(uint32_t x)
{
    x = ((x >> 16) ^ x) * 0x45d9f3bu;
    x = ((x >> 16) ^ x) * 0x45d9f3bu;
    x = (x >> 16) ^ x;
    return x;
}

static inline uint32_t _flow_hash(const uint8_t *pkt, uint32_t len)
{
    struct __eth { uint8_t dst[6]; uint8_t src[6]; uint16_t proto; };
    const struct __eth *eth;
    uint32_t ip_src, ip_dst, h;
    uint16_t port_src = 0, port_dst = 0, ip_off;

    if (len < 38u) return 0;
    eth = (const struct __eth *) pkt;

    /* proto is big-endian on the wire; the two common cases in little-endian: */
    switch (eth->proto) {
    case 0x0008u: ip_off = 26; break;   /* 0x0800 IPv4  */
    case 0x0081u: ip_off = 30; break;   /* 0x8100 VLAN  */
    default:      return 0;
    }

    ip_src = *((const uint32_t *) &pkt[ip_off    ]);
    ip_dst = *((const uint32_t *) &pkt[ip_off + 4]);
    uint8_t proto = *((const uint8_t *) &pkt[ip_off - 3]);
    if (proto == 6u || proto == 17u) {  /* TCP / UDP */
        port_src = *((const uint16_t *) &pkt[ip_off + 8    ]);
        port_dst = *((const uint16_t *) &pkt[ip_off + 8 + 2]);
    }

    h = (ip_src | ip_dst) | (uint32_t)(port_src | port_dst);
    return _hash32(h);
}

/* ── Worker thread (mirrors _worker_thread in pcap_capture.c) ───────────── */

static void *_worker_thread(void *arg)
{
    worker_context_t   *worker = (worker_context_t *) arg;
    data_spsc_ring_t   *fifo   = &worker->ebpf->fifo;
    const probe_conf_t *cfg    = worker->probe_context->config;
    uint32_t   tail;
    pkthdr_t  *hdr;
    int i, n;

    /* Spread workers across CPU cores, leaving core 0 for the reader */
    long ncores = mmt_probe_get_number_of_online_processors();
    if (ncores > 1)
        (void) move_the_current_thread_to_a_core(
            worker->index % (int)(ncores - 1) + 1, -10);

    worker_on_start(worker);

    struct timeval now;

    while (true) {
        n = data_spsc_ring_pop_bulk(fifo, &tail);

        if (n <= 0) {
            /* No packets yet — update timers and sleep briefly */
            if (cfg->input->input_mode == ONLINE_ANALYSIS)
                gettimeofday(&now, NULL);
            worker_update_timer(worker, &now);
            nanosleep((const struct timespec[]){{0, 100000L}}, NULL);
            continue;
        }

        /* Process all but the last packet first */
        n--;
        for (i = 0; i < n; i++) {
            hdr = (pkthdr_t *) data_spsc_ring_get_data(fifo, (uint32_t)i + tail);
            worker_process_a_packet(worker, hdr, (const u_char *)(hdr + 1));
            worker_update_timer(worker, &hdr->ts);
        }

        /* Last packet: check for stop sentinel before processing */
        hdr = (pkthdr_t *) data_spsc_ring_get_data(fifo, (uint32_t)n + tail);
        if (unlikely(hdr->len == BREAK_EBPF_NUMBER))
            break;

        now = hdr->ts;
        worker_process_a_packet(worker, hdr, (const u_char *)(hdr + 1));
        worker_update_timer(worker, &hdr->ts);
        data_spsc_ring_update_tail(fifo, tail, (uint32_t)n + 1u);
    }

    worker_on_stop(worker);
    return NULL;
}

/* ── SMP packet dispatch ─────────────────────────────────────────────────── */

static inline void _dispatch_smp(probe_context_t    *ctx,
                                  const struct timeval *ts,
                                  uint32_t              pkt_len,
                                  const uint8_t        *pkt_data)
{
    /* Select worker by symmetric flow hash */
    uint32_t idx = _flow_hash(pkt_data, pkt_len)
                   % (uint32_t) ctx->config->thread->thread_count;
    worker_context_t *w = ctx->smp[idx];

    pkthdr_t *hdr;
    data_spsc_ring_get_tmp_element(&w->ebpf->fifo, (void **) &hdr);

    hdr->ts        = *ts;
    hdr->caplen    = pkt_len;
    hdr->len       = pkt_len;
    hdr->user_args = NULL;
    /* Packet data immediately follows the header in the ring slot */
    memcpy(hdr + 1, pkt_data, pkt_len);

    while (unlikely(
        data_spsc_ring_push_tmp_element(&w->ebpf->fifo) != QUEUE_SUCCESS))
    {
        /* In online mode, drop the packet rather than blocking the reader */
        w->stat.pkt_dropped++;
        return;
    }
}

/* ── Fill-ring replenishment ─────────────────────────────────────────────── */

/* Return processed UMEM frames to the kernel's fill ring so it can receive
 * more packets.  Must be called after xsk_ring_cons__release(). */
static inline void _fill_ring_replenish(struct xsk_socket_info *xi,
                                         const uint64_t *addrs,
                                         unsigned int    n)
{
    uint32_t idx;
    unsigned reserved = (unsigned) xsk_ring_prod__reserve(&xi->fill, n, &idx);
    for (unsigned i = 0; i < reserved; i++)
        *xsk_ring_prod__fill_addr(&xi->fill, idx + i) = addrs[i];
    xsk_ring_prod__submit(&xi->fill, reserved);
}

/* ── AF_XDP socket lifecycle ─────────────────────────────────────────────── */

static struct xsk_socket_info *_xsk_create(const char *ifname)
{
    int ret;
    struct xsk_socket_info *xi =
        mmt_alloc_and_init_zero(sizeof(struct xsk_socket_info));
    if (!xi) return NULL;

    /* Raise RLIMIT_MEMLOCK so UMEM registration succeeds for non-root users
     * with CAP_NET_ADMIN + CAP_BPF (kernel >= 5.11 allows infinite memlock). */
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
        log_write(LOG_WARNING,
            "eBPF: setrlimit(RLIMIT_MEMLOCK) failed (%s) — may need root",
            strerror(errno));

    /* Allocate UMEM: try transparent huge pages first for lower TLB pressure,
     * fall back to regular 4 KiB pages. */
    xi->umem_size = (size_t) XSK_NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE;
    xi->umem_area = mmap(NULL, xi->umem_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (xi->umem_area == MAP_FAILED) {
        xi->umem_area = mmap(NULL, xi->umem_size,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (xi->umem_area == MAP_FAILED) {
            log_write(LOG_ERR, "eBPF: mmap UMEM (%zu B) failed: %s",
                      xi->umem_size, strerror(errno));
            mmt_probe_free(xi);
            return NULL;
        }
    }

    /* Register UMEM with the kernel.
     * fill_size = 2× default so we rarely starve the kernel of free frames. */
    struct xsk_umem_config ucfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,
    };
    ret = xsk_umem__create(&xi->umem, xi->umem_area, xi->umem_size,
                           &xi->fill, &xi->comp, &ucfg);
    if (ret) {
        log_write(LOG_ERR, "eBPF: xsk_umem__create failed: %s",
                  strerror(-ret));
        munmap(xi->umem_area, xi->umem_size);
        mmt_probe_free(xi);
        return NULL;
    }

    /* Pre-fill the fill ring with all UMEM frames so the kernel can start
     * placing incoming packets immediately. */
    unsigned fill_count = XSK_NUM_FRAMES <
        (unsigned)(XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
        ? XSK_NUM_FRAMES
        : (unsigned)(XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);

    uint32_t idx_fq;
    unsigned reserved =
        (unsigned) xsk_ring_prod__reserve(&xi->fill, fill_count, &idx_fq);
    for (unsigned i = 0; i < reserved; i++)
        *xsk_ring_prod__fill_addr(&xi->fill, idx_fq + i) =
            (uint64_t) i * XSK_UMEM__DEFAULT_FRAME_SIZE;
    xsk_ring_prod__submit(&xi->fill, reserved);

    /* Create the AF_XDP socket on queue 0.
     *
     * libbpf_flags = 0
     *   libbpf loads and attaches its own built-in XDP redirect programme.
     *   No separate clang/BPF compilation step is needed.
     *   (To use a custom programme from kern/xdp_kern.c instead, set
     *    XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD and manage the XDP prog manually.)
     *
     * xdp_flags = XDP_FLAGS_SKB_MODE
     *   Generic/SKB XDP mode works on every NIC without driver XDP support.
     *   Use XDP_FLAGS_DRV_MODE for best throughput on capable NICs.
     *
     * bind_flags = XDP_COPY
     *   Kernel copies packets into UMEM.  Works everywhere.
     *   Use XDP_ZEROCOPY for zero-copy on supported drivers. */
    struct xsk_socket_config xcfg = {
        .rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = 0,
        .xdp_flags    = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
        .bind_flags   = XDP_COPY,
    };
    ret = xsk_socket__create(&xi->xsk, ifname, 0 /* queue 0 */,
                             xi->umem, &xi->rx, NULL /* TX unused */, &xcfg);
    if (ret == -EBUSY || ret == -EEXIST) {
        /* Another XDP programme is already loaded on this interface.
         * Retry without UPDATE_IF_NOEXIST so we can co-exist with it. */
        log_write(LOG_WARNING,
            "eBPF: XDP programme already loaded on '%s', attaching alongside",
            ifname);
        xcfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        ret = xsk_socket__create(&xi->xsk, ifname, 0,
                                 xi->umem, &xi->rx, NULL, &xcfg);
    }
    if (ret) {
        log_write(LOG_ERR,
            "eBPF: xsk_socket__create on '%s' failed: %s",
            ifname, strerror(-ret));
        xsk_umem__delete(xi->umem);
        munmap(xi->umem_area, xi->umem_size);
        mmt_probe_free(xi);
        return NULL;
    }

    return xi;
}

static void _xsk_destroy(struct xsk_socket_info *xi)
{
    if (!xi) return;
    if (xi->xsk)      { xsk_socket__delete(xi->xsk);  xi->xsk  = NULL; }
    if (xi->umem)     { xsk_umem__delete(xi->umem);   xi->umem = NULL; }
    if (xi->umem_area) {
        munmap(xi->umem_area, xi->umem_size);
        xi->umem_area = NULL;
    }
    mmt_probe_free(xi);
}

/* ── Periodic traffic statistics ─────────────────────────────────────────── */

static void _print_traffic_stats(const ms_timer_t *timer, void *arg)
{
    struct timeval tv;
    probe_context_t *ctx = (probe_context_t *) arg;

    if (ctx->config->input->input_mode != ONLINE_ANALYSIS)
        return;

    /* AF_XDP exposes NIC-level drop counts via XDP statistics syscall, but
     * the libbpf helper varies by version.  Use worker-tracked drops instead,
     * which covers the more important "queue-full" drop scenario. */
    uint64_t drops = 0;
    int nw = IS_SMP_MODE(ctx) ? ctx->config->thread->thread_count : 1;
    for (int i = 0; i < nw; i++)
        drops += ctx->smp[i]->stat.pkt_dropped;
    ctx->traffic_stat.nic.drop    = drops;
    ctx->traffic_stat.nic.receive = ctx->traffic_stat.mmt.packets.receive + drops;

    gettimeofday(&tv, NULL);
    context_print_traffic_stat(ctx, &tv);
}

/* ── Resource release ────────────────────────────────────────────────────── */

static void _ebpf_capture_release(probe_context_t *ctx)
{
    int nw = IS_SMP_MODE(ctx)
             ? ctx->config->thread->thread_count
             : 1;

    if (ctx->modules.ebpf) {
        _xsk_destroy(ctx->modules.ebpf->xsk_info);
        ctx->modules.ebpf->xsk_info = NULL;
        mmt_probe_free(ctx->modules.ebpf);
        ctx->modules.ebpf = NULL;
    }

    for (int i = 0; i < nw; i++) {
        if (ctx->smp && ctx->smp[i]) {
            if (IS_SMP_MODE(ctx) && ctx->smp[i]->ebpf)
                data_spsc_ring_free(&ctx->smp[i]->ebpf->fifo);
            mmt_probe_free(ctx->smp[i]->ebpf);
            worker_release(ctx->smp[i]);
        }
    }
    mmt_probe_free(ctx->smp);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void ebpf_capture_stop(probe_context_t *ctx)
{
    /*
     * The receive loop polls with POLL_TIMEOUT_MS and checks ctx->is_exiting
     * on every iteration.  The caller (signal handler in main.c) already sets
     * ctx->is_exiting = true before calling us, so this function is a no-op.
     * It exists for API symmetry with pcap_capture_stop().
     */
    (void) ctx;
}

void ebpf_capture_release(probe_context_t *ctx)
{
    _ebpf_capture_release(ctx);
}

void ebpf_capture_start(probe_context_t *ctx)
{
    int i, ret;
    ms_timer_t stat_timer;
    struct timeval now;

    const char *ifname = ctx->config->input->input_source;

    /* AF_XDP requires a live NIC — offline PCAP-file analysis is unsupported */
    if (ctx->config->input->input_mode == OFFLINE_ANALYSIS) {
        log_write(LOG_ERR,
            "eBPF/AF_XDP does not support offline analysis. "
            "Recompile without EBPF_CAPTURE and use -t <pcap-file>.");
        return;
    }

    int nw;
    if (IS_SMP_MODE(ctx)) {
        nw = ctx->config->thread->thread_count;
        log_write(LOG_INFO,
            "Starting eBPF/AF_XDP capture on '%s' with %d worker thread(s)",
            ifname, nw);
    } else {
        nw = 1;
        log_write(LOG_INFO,
            "Starting eBPF/AF_XDP capture on '%s' (single-thread)",
            ifname);
    }

    /* ── Allocate probe-level context ──────────────────────────────────── */
    ctx->modules.ebpf =
        mmt_alloc_and_init_zero(sizeof(struct ebpf_probe_context_struct));

    ctx->modules.ebpf->xsk_info = _xsk_create(ifname);
    if (!ctx->modules.ebpf->xsk_info) {
        log_write(LOG_ERR,
            "eBPF: failed to open AF_XDP socket on '%s'", ifname);
        mmt_probe_free(ctx->modules.ebpf);
        ctx->modules.ebpf = NULL;
        return;
    }

    /* ── Allocate and start workers ─────────────────────────────────────── */
    ctx->smp = mmt_alloc_and_init_zero(sizeof(worker_context_t *) * (size_t)nw);

    for (i = 0; i < nw; i++) {
        ctx->smp[i] = worker_alloc_init(ctx->config->stack_type);

        /* In single-thread mode the worker shares the probe's output handle */
        if (!IS_SMP_MODE(ctx))
            ctx->smp[i]->output = ctx->output;

        ctx->smp[i]->index         = (uint16_t) i;
        ctx->smp[i]->probe_context = ctx;

        ctx->smp[i]->ebpf =
            mmt_alloc_and_init_zero(sizeof(struct ebpf_worker_context_struct));

        if (IS_SMP_MODE(ctx)) {
            /* Each worker has a dedicated SPSC ring fed by the reader (main thread).
             * Ring element = pkthdr_t header + snap_len bytes of packet data. */
            if (data_spsc_ring_init(
                    &ctx->smp[i]->ebpf->fifo,
                    ctx->config->thread->thread_queue_packet_threshold,
                    sizeof(pkthdr_t) + ctx->config->input->snap_len)) {
                ABORT("eBPF: cannot allocate FIFO for worker %d. "
                      "Reduce thread-queue or thread-nb.", i);
            }
            pthread_create(&ctx->smp[i]->ebpf->thread_handler, NULL,
                           _worker_thread, ctx->smp[i]);
        } else {
            worker_on_start(ctx->smp[0]);
        }
    }

    /* ── Periodic statistics timer ──────────────────────────────────────── */
    ms_timer_init(&stat_timer,
                  ctx->config->stat_period * S2MS,
                  _print_traffic_stats, ctx);

    struct xsk_socket_info *xi = ctx->modules.ebpf->xsk_info;
    int xsk_fd = xsk_socket__fd(xi->xsk);

    /* Saved frame addresses for fill-ring replenishment (stack allocation,
     * XSK_RX_BATCH × 8 B = 512 B — well within safe stack limits). */
    uint64_t recycled_addrs[XSK_RX_BATCH];

    /* ── Main receive loop ──────────────────────────────────────────────── */
    while (!ctx->is_exiting) {

        /* Sleep until at least one packet arrives or the timeout fires */
        struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
        ret = poll(&pfd, 1, POLL_TIMEOUT_MS);

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_write(LOG_ERR, "eBPF: poll() error: %s", strerror(errno));
            break;
        }

        /* Drain one batch of received packets from the RX ring */
        uint32_t idx_rx;
        unsigned rcvd = (unsigned)
            xsk_ring_cons__peek(&xi->rx, XSK_RX_BATCH, &idx_rx);

        if (rcvd == 0) {
            /* Timeout with no packets — fire timers */
            gettimeofday(&now, NULL);
            if (!IS_SMP_MODE(ctx))
                worker_update_timer(ctx->smp[0], &now);
            ms_timer_set_time(&stat_timer, &now);
            continue;
        }

        gettimeofday(&now, NULL);

        for (unsigned j = 0; j < rcvd; j++) {
            const struct xdp_desc *desc =
                xsk_ring_cons__rx_desc(&xi->rx, idx_rx + j);
            uint32_t        pkt_len  = desc->len;
            uint64_t        addr     = desc->addr;
            const uint8_t  *pkt_data =
                (const uint8_t *) xsk_umem__get_data(xi->umem_area, addr);

            if (IS_SMP_MODE(ctx)) {
                /* _dispatch_smp() memcpy's packet data into the SPSC ring
                 * before returning, so the UMEM frame is safe to recycle. */
                _dispatch_smp(ctx, &now, pkt_len, pkt_data);
            } else {
                pkthdr_t hdr = {
                    .ts        = now,
                    .caplen    = pkt_len,
                    .len       = pkt_len,
                    .user_args = NULL,
                };
                worker_process_a_packet(ctx->smp[0], &hdr, pkt_data);
                worker_update_timer(ctx->smp[0], &now);
            }

            ctx->traffic_stat.mmt.bytes.receive   += pkt_len;
            ctx->traffic_stat.mmt.packets.receive ++;
            recycled_addrs[j] = addr;   /* save for fill-ring replenishment */
        }

        /* Hand the RX ring slots back to the kernel */
        xsk_ring_cons__release(&xi->rx, rcvd);

        /* Return processed UMEM frames to the fill ring so the kernel
         * can place new packets into them */
        _fill_ring_replenish(xi, recycled_addrs, rcvd);

        ms_timer_set_time(&stat_timer, &now);
    }

    /* ── Shutdown ───────────────────────────────────────────────────────── */
    if (IS_SMP_MODE(ctx)) {
        pkthdr_t *stop_hdr;

        /* Enqueue a stop sentinel (len == BREAK_EBPF_NUMBER == 0) for each
         * worker thread so it exits its loop cleanly. */
        for (i = 0; i < ctx->config->thread->thread_count; i++) {
            data_spsc_ring_get_tmp_element(
                &ctx->smp[i]->ebpf->fifo, (void **) &stop_hdr);
            stop_hdr->len = BREAK_EBPF_NUMBER;
            while (unlikely(
                data_spsc_ring_push_tmp_element(&ctx->smp[i]->ebpf->fifo)
                != QUEUE_SUCCESS))
            {
                nanosleep((const struct timespec[]){{0, 10000L}}, NULL);
            }
        }

        /* Wait for all workers to drain their queues and exit */
        for (i = 0; i < ctx->config->thread->thread_count; i++) {
            ret = pthread_join(ctx->smp[i]->ebpf->thread_handler, NULL);
            if (ret != 0)
                log_write(LOG_ERR, "eBPF: cannot join worker %d: %s",
                          i, strerror(errno));
        }
    } else {
        worker_on_stop(ctx->smp[0]);
    }

    worker_print_common_statistics(ctx);
    _ebpf_capture_release(ctx);
}
