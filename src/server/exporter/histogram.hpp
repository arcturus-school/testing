#ifndef _HISTOGRAM_H
#define _HISTOGRAM_H

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>

#include "../utils/log.hpp"
#include "../utils/tools.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <yaml-cpp/yaml.h>

class Histogram {
    int fd;

    YAML::Node histograms;

    struct perf_buffer* pb = nullptr;

  public:
    Histogram(int, YAML::Node);
    ~Histogram();
    error_t init();
    void    observe();
};

#endif