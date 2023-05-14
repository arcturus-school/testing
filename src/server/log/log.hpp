#pragma once

#include "../config/env.hpp"
#include <iostream>
#include <string>

#define NONE "\033[0m"
#define RED(a) "\033[31m" a NONE
#define GREEN(a) "\033[32m" a NONE
#define YELLO(a) "\033[33m" a NONE
#define BLUE(a) "\033[34m" a NONE
#define PURPLE(a) "\033[35m" a NONE

namespace Log {
template <typename... Args>
void log(const Args&... args) {
    if (debug) (std::cout << ... << args);
}

template <typename... Args>
void warn(const Args&... args) {
    if (debug) (std::cout << PURPLE("warn: ") << ... << args);
}

template <typename... Args>
void error(const Args&... args) {
    (std::cout << RED("error: ") << ... << args);
}
} // namespace Log
