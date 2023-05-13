#ifndef __TCPRTT_H
#define __TCPRTT_H

#define MAX_SLOTS 27

struct data_t {
    unsigned long long ts;    // 当前时间戳
    unsigned long long rtt;   // 往返延迟
    unsigned int       daddr; // 目的地址
    unsigned int       saddr; // 源地址
    unsigned short     dport; // 目的端口
    unsigned short     sport; // 源端口
};

#endif