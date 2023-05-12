#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN 16

#define AF_INET 2
#define AF_INET6 10

struct data_t {
    // 源地址
    union {
        unsigned int  saddr_v4;
        unsigned char saddr_v6[16];
    };
    // 目的地址
    union {
        unsigned int  daddr_v4;
        unsigned char daddr_v6[16];
    };
    char               comm[TASK_COMM_LEN]; // 进程名
    int                af;                  // 协议族
    unsigned int       tgid;                // 进程 ID
    unsigned short     lport;               // 源端口
    unsigned short     dport;               // 目的端口
    unsigned long long delta;               // 建连耗时
    unsigned long long ts;                  // 时间戳
};

#endif