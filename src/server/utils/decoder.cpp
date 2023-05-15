#include "decoder.hpp"

std::string static_map(unsigned long long in, const YAML::Node& map) {
    std::string key = std::to_string(in);

    if (!map) {
        Log::warn("Empty mapping.\n");

        return key;
    }

    if (map[key]) {
        return map[key].as<std::string>();
    }

    return key;
}

std::string inet(int af, const void* ip) {
    char buf[INET6_ADDRSTRLEN];

    union {
        struct in_addr  x4;
        struct in6_addr x6;
    } addr;

    // 这里没有根据 config 的 type 来定大小, 而是一开始就确定的
    if (af == AF_INET) {
        addr.x4.s_addr = *(unsigned int*)ip;
        inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
    } else if (af == AF_INET6) {
        memcpy(&addr.x6.s6_addr, (unsigned short*)ip, sizeof(addr.x6.s6_addr));
        inet_ntop(AF_INET6, &addr, buf, INET6_ADDRSTRLEN);
    } else {
        Log::warn("Not support family.\n");
        return "";
    }

    return std::string(buf);
}