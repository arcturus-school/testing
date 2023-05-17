#include "tcpconnlat.h"
#include "../common/helpers.h"
#include "./dist/tcpconnlat.skel.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

static volatile sig_atomic_t exiting = 0;

struct Configs {
    __u64 min_us;
    pid_t pid;
    bool  timestamp;
    bool  lport;
    bool  verbose;
};

static struct Configs configs = {
    .verbose   = true,
    .timestamp = true,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG && !configs.verbose) return 0;

    return vfprintf(stderr, format, args);
}

static void signal_handler(int signo) {
    exiting = true;
}

void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    const struct data_t* e = data;

    char src[46];
    char dst[46];

    // 源地址和目的地址
    union {
        struct in_addr  x4;
        struct in6_addr x6;
    } s, d;

    static __u64 start_ts;

    if (configs.timestamp) {
        if (start_ts == 0) start_ts = e->ts;

        printf("%-9.3f ", (e->ts - start_ts) / 1000000.0);
    }

    if (e->af == AF_INET) {
        s.x4.s_addr = e->saddr_v4;
        d.x4.s_addr = e->daddr_v4;
    } else if (e->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "broken event: event->af=%d", e->af);
        return;
    }

    if (configs.lport) {
        printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", e->tgid, e->comm, e->af == AF_INET ? 4 : 6,
            inet_ntop(e->af, &s, src, sizeof(src)), e->lport, inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport), e->delta / 1000.0);
    } else {
        printf("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f\n", e->tgid, e->comm, e->af == AF_INET ? 4 : 6,
            inet_ntop(e->af, &s, src, sizeof(src)), inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport), e->delta / 1000.0);
    }
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void display(struct bpf_map* map) {
    int fd = bpf_map__fd(map), err;

    struct perf_buffer_opts opt = {
        .sample_cb = handle_event,
        .lost_cb   = handle_lost_events,
    };

    struct perf_buffer* pb = perf_buffer__new(fd, PERF_BUFFER_PAGES, &opt);

    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer: %d\n", errno);

        perf_buffer__free(pb);

        return;
    }

    if (configs.timestamp) printf("%-9s ", ("TIME(s)"));

    if (configs.lport) {
        printf("%-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n", "PID", "COMM", "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)");
    } else {
        printf("%-6s %-12s %-2s %-16s %-16s %-5s %s\n", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT", "LAT(ms)");
    }

    while (true) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }

        if (exiting) {
            break;
        }
    }

    perf_buffer__free(pb);
}

int main(int argc, char** argv) {
    struct tcpconnlat_bpf* obj;

    int err;

    libbpf_set_print(libbpf_print_fn);

    obj = tcpconnlat_bpf__open();

    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    obj->rodata->min_us = configs.min_us;
    obj->rodata->k_tgid = configs.pid;

    err = tcpconnlat_bpf__load(obj);

    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        tcpconnlat_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    err = tcpconnlat_bpf__attach(obj);

    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        tcpconnlat_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    signal(SIGINT, signal_handler);

    display(obj->maps.events);

    tcpconnlat_bpf__destroy(obj);

    return 0;
}