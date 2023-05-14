#ifndef _LOG_H
#define _LOG_H

#include <iostream>
#include <string>

#define NONE "\033[0m"
#define RED(a) "\033[31m" a NONE
#define GREEN(a) "\033[32m" a NONE
#define YELLO(a) "\033[33m" a NONE
#define BLUE(a) "\033[34m" a NONE
#define PURPLE(a) "\033[35m" a NONE

class Log {
  public:
    template <typename... Args>
    static void log(const Args&... args);

    template <typename... Args>
    static void warn(const Args&... args);

    template <typename... Args>
    static void error(const Args&... args);
};

extern bool enable_debug;

template <typename... Args>
void Log::log(const Args&... args) {
    if (enable_debug) (std::cout << ... << args);
}

template <typename... Args>
void Log::warn(const Args&... args) {
    if (enable_debug) (std::cout << PURPLE("warn: ") << ... << args);
}

template <typename... Args>
void Log::error(const Args&... args) {
    (std::cout << RED("error: ") << ... << args);
}

#endif