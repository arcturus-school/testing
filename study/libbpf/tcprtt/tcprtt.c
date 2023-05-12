#define _DEFAULT_SOURCE

#include "tcprtt.h"
#include "../common/helpers.h"
#include "dist/tcprtt.skel.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

struct Configs {
    __u16  lport;     // 本地端口
    __u16  rport;     // 远程端口
    __u32  laddr;     // 本地地址
    __u32  raddr;     // 远程地址
    bool   timestamp; // 是否显示时间戳
    bool   ms;        // 单位是否是毫秒
    bool   verbose;   // 是否显示日志信息
    time_t duration;  // 监控持续时间(不写需要按 ctrl+c 退出)
};

struct Configs configs = {
    .ms        = false,
    .verbose   = true,
    .timestamp = true,
};

static volatile bool exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG && !configs.verbose) return 0;

    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}

static void print_events_header() {
    if (configs.timestamp) printf("%-9s", "TIME(s)");

    const char* rtt = configs.ms ? "RTT(ms)" : "RTT(us)";

    printf("%-12s %-16s %-16s %-4s %-4s\n", rtt, "SADDR", "DADDR", "SPORT", "DPORT");
}

static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    const struct data_t* event = data;

    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

    if (configs.timestamp) {
        struct tm* tm;
        char       ts[32];
        time_t     t;

        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);

        printf("%-9s", ts);
    }

    printf("%-12lld %-16s %-16s %-4d %-4d\n", event->rtt, inet_ntop(AF_INET, &event->saddr, saddr, sizeof(saddr)),
        inet_ntop(AF_INET, &event->daddr, daddr, sizeof(daddr)), ntohs(event->sport), ntohs(event->dport));
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void display(struct bpf_map* map) {
    struct perf_buffer* pb;

    __u64 time_end = 0;

    if (configs.duration) {
        time_end = get_ktime_ns() + configs.duration * NSEC_PER_SEC;
    }

    int fd = bpf_map__fd(map), err;

    struct perf_buffer_opts opt = {
        .sample_cb = handle_event,
        .lost_cb   = handle_lost_events,
    };

    pb = perf_buffer__new(fd, 16, &opt);

    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer: %d\n", -errno);
        perf_buffer__free(pb);

        return;
    }

    print_events_header();

    while (true) {
        err = perf_buffer__poll(pb, 100);

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }

        if (exiting || (configs.duration && get_ktime_ns() > time_end)) {
            break;
        }
    }

    perf_buffer__free(pb);
}

int main(int argc, char** argv) {
    struct tcprtt_bpf*  obj;
    struct bpf_program* prog;

    int err;

    libbpf_set_print(libbpf_print_fn);

    obj = tcprtt_bpf__open();

    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return EXIT_FAILURE;
    }

    obj->rodata->k_sport = configs.lport;
    obj->rodata->k_dport = configs.rport;
    obj->rodata->k_saddr = configs.laddr;
    obj->rodata->k_daddr = configs.raddr;
    obj->rodata->ms      = configs.ms;

    bpf_object__for_each_program(prog, obj->obj) {
        // 用于忽略不兼容的插桩, 不过这里只有 kprobe_tcp_rcv_established
        // 所以写不写这段代码都无所谓
        if (!find_ksym_by_name(bpf_program__name(prog))) {
            bpf_program__set_autoload(prog, false);
        }
    }

    err = tcprtt_bpf__load(obj);

    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        tcprtt_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    err = tcprtt_bpf__attach(obj);

    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        tcprtt_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    // 接收中断信号(ctrl+c)
    signal(SIGINT, sig_handler);

    printf("Tracing TCP RTT");

    if (configs.duration) {
        printf(" for %ld secs.\n", configs.duration);
    } else {
        printf("... Hit Ctrl-C to end.\n");
    }

    display(obj->maps.events);

    tcprtt_bpf__destroy(obj);

    return EXIT_SUCCESS;
}