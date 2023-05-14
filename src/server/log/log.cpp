#include "log.hpp"

namespace Log {
template <typename... Args>
void log(const Args&... args);

template <typename... Args>
void error(const Args&... args);
} // namespace Log
