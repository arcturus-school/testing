#include "decoder.hpp"

std::string static_map(int in, YAML::Node& map) {
    std::string key = std::to_string(in);

    if (!map) {
        Log::warn("Empty mapping.\n");

        return key;
    }

    return map[key].as<std::string>();
}

std::string inet(int af, const void* ip) {
    char addr[INET6_ADDRSTRLEN];

    if (af == AF_INET) {
        struct in_addr* v4 = (struct in_addr*)ip;
        inet_ntop(AF_INET, v4, addr, INET_ADDRSTRLEN);
    } else if (af == AF_INET6) {
        struct in6_addr* v6 = (struct in6_addr*)ip;
        inet_ntop(AF_INET6, addr, addr, INET6_ADDRSTRLEN);
    } else {
        Log::warn("Not support family.\n");
        return "";
    }

    return std::string(addr);
}