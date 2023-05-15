#ifndef _EXPORTER_H
#define _EXPORTER_H

#include <bpf/libbpf.h>
#include <map>
#include <sstream>
#include <string>

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>
#include <yaml-cpp/yaml.h>

#include "../utils/log.hpp"
#include "counter.hpp"
#include "histogram.hpp"

struct Program {
    bpf_object* object;
    YAML::Node  metrics;
};

// 打开所有 ebpf 对象
error_t open_all_bpf_object();

// 加载全部 ebpf 对象
error_t load_all_bpf_object();

// 关闭所有 ebpf obj
void close_bpf_object();

// 对所有程序进行插桩
void attach_all_bpf_program();

// 为所有 metrics 注册监听事件
void register_all_event_handle();

// 运行所有监听事件
void observe();

#endif