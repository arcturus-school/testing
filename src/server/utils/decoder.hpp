#ifndef _DECODER_H
#define _DECODER_H

#include "log.hpp"

// 根据键获取值
std::string static_map(_u64_m, const YAML::Node&);

// 数字 IP 转字符串
std::string inet(int, const void*);

#endif