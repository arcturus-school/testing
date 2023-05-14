#ifndef _EXPORTER_H
#define _EXPORTER_H

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>

#include "../config/config.hpp"
#include "../utils/log.hpp"
#include <bpf/libbpf.h>
#include <map>
#include <sstream>
#include <string>

void run_exporter();

// 打开所有 ebpf 对象
error_t open_all_bpf_object();

// 加载全部 ebpf 对象
error_t load_all_bpf_object();

// 关闭所有 ebpf obj
void close_bpf_object();

// 对所有程序进行插桩
void attach_all_bpf_program();

#endif