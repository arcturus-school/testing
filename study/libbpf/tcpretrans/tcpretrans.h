#ifndef _TCPRETRANS_H
#define _TCPRETRANS_H

#define TASK_COMM_LEN 16

#define AF_INET 2
#define AF_INET6 10

#define RETRANSMIT 1
#define TLP 2

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
    unsigned long long ts;                  // 时间戳
    unsigned long long state;               // TCP 状态
    unsigned long long type;                // 报文类型
};

struct flow_key_t {
    union {
        unsigned int  saddr_v4;
        unsigned char saddr_v6[16];
    };
    union {
        unsigned int  daddr_v4;
        unsigned char daddr_v6[16];
    };
    unsigned short lport;
    unsigned short dport;
    int            af;
};

#endif