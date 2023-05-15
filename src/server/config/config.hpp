#ifndef _CONFIG_H
#define _CONFIG_H

#include "../exporter/exporter.hpp"
#include "../utils/file.hpp"
#include "../utils/log.hpp"

#include <bpf/libbpf.h>
#include <map>
#include <string>
#include <yaml-cpp/yaml.h>

// 读取配置文件
error_t read_config();

#endif