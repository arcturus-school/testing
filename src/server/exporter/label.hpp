#ifndef _LABEL_H
#define _LABEL_H

#include "../utils/decoder.hpp"
#include "../utils/tools.hpp"

class Label {
  public:
    std::string name;       // 标签名
    std::string type;       // 标签类型
    TYPES       type_num;   // 标签类型
    size_t      size   = 0; // 标签占用字节数
    size_t      offset = 0; // 标签偏移量
    char*       buffer;     // 用于读取 label 数据
    Decoder     decoder;    // 编码器

    Label(const YAML::Node& label);

    ~Label();
};

std::map<std::string, std::string> parse_labels(void*, std::vector<Label>&, int start = 0);

#endif