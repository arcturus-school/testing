#ifndef _CONFIG_H
#define _CONFIG_H

#include "../utils/file.hpp"
#include "../utils/log.hpp"
#include <bpf/libbpf.h>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

struct Program {
    std::string name;
    YAML::Node  metrics;
};

// 关闭所有 ebpf obj
void close_bpf_object();

// 读取配置文件
error_t read_config();

#endif