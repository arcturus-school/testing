#include "biolatency.h"
#include "../common/helpers.h"
#include "./dist/biolatency.skel.h"
#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct Configs {
    time_t interval; // 监控时间间隔
    int    times;    // 监控次数
    bool   timestamp;
    bool   queued;
    bool   ms;
    bool   verbose;
};

struct Configs configs = {
    .interval = 9999999,
    .verbose  = true,
    .ms       = false,
};

static volatile bool exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG && !configs.verbose) return 0;

    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}

// struct Flags {
//     int         bit;
//     const char* str;
// };

// static void print_cmd_flags(int cmd_flags) {
//     static struct Flags flags[] = {
//         { REQ_NOWAIT, "NoWait-" },
//         { REQ_BACKGROUND, "Background-" },
//         { REQ_RAHEAD, "ReadAhead-" },
//         { REQ_PREFLUSH, "PreFlush-" },
//         { REQ_FUA, "FUA-" },
//         { REQ_INTEGRITY, "Integrity-" },
//         { REQ_IDLE, "Idle-" },
//         { REQ_NOMERGE, "NoMerge-" },
//         { REQ_PRIO, "Priority-" },
//         { REQ_META, "Metadata-" },
//         { REQ_SYNC, "Sync-" },
//     };

//     static const char* ops[] = {
//         [REQ_OP_READ]           = "Read",
//         [REQ_OP_WRITE]          = "Write",
//         [REQ_OP_FLUSH]          = "Flush",
//         [REQ_OP_DISCARD]        = "Discard",
//         [REQ_OP_SECURE_ERASE]   = "SecureErase",
//         [REQ_OP_ZONE_RESET]     = "ZoneReset",
//         [REQ_OP_WRITE_SAME]     = "WriteSame",
//         [REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll",
//         [REQ_OP_WRITE_ZEROES]   = "WriteZeroes",
//         [REQ_OP_ZONE_OPEN]      = "ZoneOpen",
//         [REQ_OP_ZONE_CLOSE]     = "ZoneClose",
//         [REQ_OP_ZONE_FINISH]    = "ZoneFinish",
//         [REQ_OP_SCSI_IN]        = "SCSIIn",
//         [REQ_OP_SCSI_OUT]       = "SCSIOut",
//         [REQ_OP_DRV_IN]         = "DrvIn",
//         [REQ_OP_DRV_OUT]        = "DrvOut",
//     };

//     int i;

//     printf("flags = ");

//     for (i = 0; i < ARRAY_SIZE(flags); i++) {
//         if (cmd_flags & flags[i].bit) {
//             printf("%s", flags[i].str);
//         }
//     }

//     if ((cmd_flags & REQ_OP_MASK) < ARRAY_SIZE(ops)) {
//         printf("%s", ops[cmd_flags & REQ_OP_MASK]);
//     } else {
//         printf("Unknown");
//     }
// }

// 打印直方图
static int print_log2_hists(struct bpf_map* hists) {
    struct disk_latency_key_t cur = { .op = -1 }, next;

    __u64 data;

    const char* units = configs.ms ? "ms" : "us";

    int err, fd = bpf_map__fd(hists);

    unsigned int slots[MAX_SLOTS] = { 0 };

    // 读取 Map 中的全部数据
    while (!bpf_map_get_next_key(fd, &cur, &next)) {
        err = bpf_map_lookup_elem(fd, &next, &data);

        if (err < 0) {
            fprintf(stderr, "Failed to lookup hist: %d\n", err);
            return -1;
        }

        slots[next.slot] += data;

        cur = next;
    }

    printf("\n");
    print_log2_hist(slots, MAX_SLOTS, units);

    cur.op = -1;

    // 清空 Map
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

int main(int argc, char** argv) {
    struct biolatency_bpf* obj;

    int err;

    libbpf_set_print(libbpf_print_fn);

    obj = biolatency_bpf__open();

    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return EXIT_FAILURE;
    }

    obj->rodata->ms     = configs.ms;
    obj->rodata->queued = configs.queued;

    err = biolatency_bpf__load(obj);

    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);

        biolatency_bpf__destroy(obj);

        return err != 0;
    }

    err = biolatency_bpf__attach(obj);

    if (err) {
        fprintf(stderr, "Failed to attach BPF object: %d\n", err);

        biolatency_bpf__destroy(obj);

        return err != 0;
    }

    signal(SIGINT, sig_handler);

    printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

    struct tm* tm;
    char       ts[32];
    time_t     t;

    while (true) {
        sleep(configs.interval);

        printf("\n");

        if (configs.timestamp) {
            time(&t);
            tm = localtime(&t);
            strftime(ts, sizeof(ts), "%H:%M:%S", tm);
            printf("%-8s\n", ts);
        }

        err = print_log2_hists(obj->maps.bio_latency);

        if (err) break;

        if (exiting || --configs.times == 0) break;
    }

    biolatency_bpf__destroy(obj);

    return err != 0;
}