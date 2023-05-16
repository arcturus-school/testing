#include "decoder.hpp"

std::string static_map(_u64_m in, const YAML::Node& map) {
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

    switch (af) {
    case AF_INET: {
        addr.x4.s_addr = *(_u32_m*)ip;
        inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
        break;
    }
    case AF_INET6: {
        memcpy(&addr.x6.s6_addr, (_u8_m*)ip, sizeof(addr.x6.s6_addr));
        inet_ntop(AF_INET6, &addr, buf, INET6_ADDRSTRLEN);
        break;
    }
    default:
        Log::warn("Not support family.\n");
        return "unknown";
    }

    return std::string(buf);
}