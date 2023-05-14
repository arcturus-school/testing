#ifndef _CONFIG_H
#define _CONFIG_H

#include "../utils/file.hpp"
#include "../utils/log.hpp"

#include <bpf/libbpf.h>
#include <map>
#include <string>
#include <yaml-cpp/yaml.h>

struct Program {
    bpf_object* object;
    YAML::Node  metrics;
};

// 关闭所有 ebpf obj
void close_bpf_object();

// 读取配置文件
error_t read_config();

#endif