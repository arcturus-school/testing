#include "decoder.hpp"

Decoder::Decoder(const YAML::Node& decoder) {
    if (!decoder || !decoder["name"]) {
        name = "unknown";
        return;
    }

    name = decoder["name"].as<std::string>();

    if (name == "static_map") {
        if (!decoder["static_map"]) {
            Log::warn("static_map is missing.\n");
        }

        map = decoder["static_map"].as<std::map<std::string, std::string>>();
    }
}

std::string Decoder::static_map(_u64_m in) {
    std::string key = std::to_string(in);

    if (map.empty()) {
        Log::warn("Empty mapping.\n");

        return key;
    }

    if (map.find(key) != map.end()) {
        return map[key];
    }

    return key;
}

std::string Decoder::inet(int af, const void* ip) {
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