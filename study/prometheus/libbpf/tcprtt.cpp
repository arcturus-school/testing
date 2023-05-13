#include <prometheus/client_metric.h>
#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>

#include <arpa/inet.h>
#include <array>
#include <bpf/bpf.h>
#include <iostream>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../../libbpf/common/helpers.h"
#include "dist/tcprtt.skel.h"
#include "tcprtt.h"

struct Configs {
    __u16 lport;   // 本地端口
    __u16 rport;   // 远程端口
    __u32 laddr;   // 本地地址
    __u32 raddr;   // 远程地址
    __u32 port;    // 服务端口
    bool  ms;      // 单位是否是毫秒
    bool  verbose; // 是否显示日志信息
};

struct Configs configs = { .port = 8000, .ms = false, .verbose = false };

static volatile bool exiting;

std::vector<double> create_buckets() {
    std::vector<double> buckets;

    for (int i = 0; i <= MAX_SLOTS; i++) {
        buckets.push_back((1ULL << (i + 1)) >> 1);
    }

    return buckets;
}

// create a metrics registry
auto registry = std::make_shared<prometheus::Registry>();

auto& hist_family = prometheus::BuildHistogram().Name("tcp_rtt").Help("Round Trip Time").Register(*registry);

auto& hist = hist_family.Add({ { "address", "all" } }, create_buckets());

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG && !configs.verbose) return 0;

    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}

static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    const struct data_t* event = (struct data_t*)data;

    hist.Observe(event->rtt);
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void observe(struct bpf_map* map) {
    struct perf_buffer* pb;

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

    while (true) {
        err = perf_buffer__poll(pb, 100);

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
    struct tcprtt_bpf* obj;

    libbpf_set_print(libbpf_print_fn);

    obj = tcprtt_bpf__open();

    if (!obj) {
        std::cerr << "Failed to open BPF object." << std::endl;

        return EXIT_FAILURE;
    }

    std::cout << "Open BPF object successfully." << std::endl;

    obj->rodata->k_sport = configs.lport;
    obj->rodata->k_dport = configs.rport;
    obj->rodata->k_saddr = configs.laddr;
    obj->rodata->k_daddr = configs.raddr;
    obj->rodata->ms      = configs.ms;

    int err = tcprtt_bpf__load(obj);

    if (err) {
        std::cerr << "Failed to load BPF object: " << err << std::endl;

        tcprtt_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    std::cout << "Load BPF object successfully." << std::endl;

    err = tcprtt_bpf__attach(obj);

    if (err) {
        std::cerr << "Failed to attach BPF programs: " << err << std::endl;

        tcprtt_bpf__destroy(obj);

        return EXIT_FAILURE;
    }

    std::cout << "Attach BPF programs successfully." << std::endl;

    // 接收中断信号(ctrl+c)
    signal(SIGINT, sig_handler);

    std::ostringstream oss;

    oss << "127.0.0.1:" << configs.port;

    // create an http server running on port 8000
    prometheus::Exposer exposer{ oss.str() };

    // ask the exposer to scrape the registry on incoming HTTP requests
    exposer.RegisterCollectable(registry);

    std::cout << "Server is running at "
              << "\033[34m"
              << "http://" << oss.str() << "/metrics"
              << "\033[0m" << std::endl;

    observe(obj->maps.events);

    tcprtt_bpf__destroy(obj);

    return EXIT_SUCCESS;
}
