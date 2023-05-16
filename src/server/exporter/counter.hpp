#ifndef _COUNTER_H
#define _COUNTER_H

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>

#include "../utils/decoder.hpp"
#include "../utils/log.hpp"
#include "../utils/tools.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <yaml-cpp/yaml.h>

class Counter {
  public:
    int fd;

    YAML::Node counter;

    struct perf_buffer* pb = nullptr;

    prometheus::Family<prometheus::Counter>* count;

    std::vector<int>   sizes;
    std::vector<int>   offsets;
    std::vector<char*> bufs;

    std::vector<YAML::Node>  decoders;
    std::vector<std::string> types;
    std::vector<std::string> names;

    Counter(int, const YAML::Node&);
    ~Counter();
    error_t init();
    void    observe();
};

#endif