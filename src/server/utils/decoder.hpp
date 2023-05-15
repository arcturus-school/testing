#ifndef _DECODER_H
#define _DECODER_H

#include "log.hpp"
#include <arpa/inet.h>
#include <string>
#include <yaml-cpp/yaml.h>

// 根据键获取值
std::string static_map(unsigned long long, const YAML::Node&);

// 数字 IP 转字符串
std::string inet(int, const void*);

#endif