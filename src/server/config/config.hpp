#pragma once

#include "../log/log.hpp"
#include "../utils/file.hpp"
#include <bpf/libbpf.h>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

// 保存所有 metrics 的配置
extern std::vector<YAML::Node> metrics;

// 保存所有 ebpf 程序
extern std::vector<bpf_object*> programs;

// 关闭所有 ebpf obj
void close_bpf_object();

// 读取配置文件
error_t read_config();