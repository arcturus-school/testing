#ifndef _DECODER_H
#define _DECODER_H

#include "log.hpp"

class Decoder {
  public:
    std::string name;

    std::map<std::string, std::string> map;

    // 根据键获取值
    std::string static_map(_u64_m);

    // 数字 IP 转字符串
    static std::string inet(int, const void*);

    Decoder(const YAML::Node&);

    bool has() {
        return name != "unknown";
    }
};

#endif