#include "tcpretrans.h"
#include "../common/helpers.h"
#include "./dist/tcpretrans.skel.h"
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
    bool timestamp;
    bool ipv4;
    bool ipv6;
    bool count;
    bool verbose;
    int  interval;
    int  times;
};

static struct Configs configs = {
    .count     = true,
    .verbose   = true,
    .timestamp = true,
    .interval  = 99999,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG && !configs.verbose) return 0;

    return vfprintf(stderr, format, args);
}

static void signal_handler(int signo) {
    exiting = true;
}

static char* tcp_states[] = {
    "UNKNOWN",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "NEW_SYN_RECV",
};

void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    const struct data_t* e = data;

    char src[46];
    char dst[46];

    // 源地址和目的地址
    union {
        struct in_addr  x4;
        struct in6_addr x6;
    } s, d;

    if (configs.timestamp) {
        struct tm* tm;
        char       ts[32];
        time_t     t;

        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);

        printf("%-9s ", ts);
    }

    if (e->af == AF_INET) {
        s.x4.s_addr = e->saddr_v4;
        d.x4.s_addr = e->daddr_v4;
    } else if (e->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "Broken event: event->af=%d", e->af);
        return;
    }

    char* type   = e->type == RETRANSMIT ? "R" : "L";
    char* states = tcp_states[e->state];

    printf("%-6d %-12s %-2d %-20s %-6d %-2s> %-20s %-6d %-15s\n", e->tgid, e->comm, e->af == AF_INET ? 4 : 6,
        inet_ntop(e->af, &s, src, sizeof(src)), e->lport, type, inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport), states);
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int print_count(int fd) {
    char src[46];
    char dst[46];

    union {
        struct in_addr  x4;
        struct in6_addr x6;
    } s, d;

    struct flow_key_t cur = { .af = 0 }, next;

    __u32 data;

    int err;

    while (!bpf_map_get_next_key(fd, &cur, &next)) {
        err = bpf_map_lookup_elem(fd, &next, &data);

        if (err < 0) {
            fprintf(stderr, "Failed to lookup hist: %d\n", err);
            return -1;
        }

        if (next.af == AF_INET) {
            s.x4.s_addr = next.saddr_v4;
            d.x4.s_addr = next.daddr_v4;
        } else if (next.af == AF_INET6) {
            memcpy(&s.x6.s6_addr, next.saddr_v6, sizeof(s.x6.s6_addr));
            memcpy(&d.x6.s6_addr, next.daddr_v6, sizeof(d.x6.s6_addr));
        } else {
            fprintf(stderr, "Broken event: event->af=%d", next.af);
            return -1;
        }

        printf("%-20s %-6d %-20s %-6d %-10d\n", inet_ntop(next.af, &s, src, sizeof(src)), next.lport,
            inet_ntop(next.af, &d, dst, sizeof(dst)), ntohs(next.dport), data);

        cur = next;
    }

    cur.af = 0;

    while (!bpf_map_get_next_key(fd, &cur, &next)) {
        err = bpf_map_delete_elem(fd, &next);

        if (err < 0) {
            fprintf(stderr, "Failed to cleanup hist : %d\n", err);
            return -1;
        }

        cur = next;
    }

    return 0;
}

void display_count(struct bpf_map* map) {
    printf("Tracing tcp retransmission... Hit Ctrl-C to end.\n");

    printf("%-20s %-6s %-20s %-6s %-10s\n", "LADDR", "LPORT", "RADDR", "RPORT", "RETRANSMITS");

    int err, fd = bpf_map__fd(map);

    while (true) {
        sleep(configs.interval);

        printf("\n");

        err = print_count(fd);

        if (err || exiting) break;

        if (configs.times && --configs.times == 0) break;
    }
}

void display_info(struct bpf_map* map) {
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

    if (configs.timestamp) printf("%-9s ", ("TIME"));

    printf("%-6s %-12s %-2s %-20s %-6s %-2s %-20s %-6s %-15s\n", "PID", "COMM", "IP", "LADDR", "LPORT", "T>", "DADDR", "DPORT", "STATE");

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
    struct tcpretrans_bpf* obj;

    int err;

    libbpf_set_print(libbpf_print_fn);

    obj = tcpretrans_bpf__open();

    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    obj->rodata->count = configs.count;
    obj->rodata->ipv4  = configs.ipv4;
    obj->rodata->ipv6  = configs.ipv6;

    err = tcpretrans_bpf__load(obj);

    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        tcpretrans_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    err = tcpretrans_bpf__attach(obj);

    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        tcpretrans_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    signal(SIGINT, signal_handler);

    if (configs.count) {
        display_count(obj->maps.counts);
    } else {
        display_info(obj->maps.events);
    }

    tcpretrans_bpf__destroy(obj);

    return 0;
}