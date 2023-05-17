#pragma once

#include <string>

struct Configs {
    bool        debug;
    std::string config_path;
};

extern struct Configs configs;