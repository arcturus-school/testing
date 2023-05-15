#ifndef _HISTOGRAM_H
#define _HISTOGRAM_H

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>

#include "../utils/decoder.hpp"
#include "../utils/log.hpp"
#include "../utils/tools.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <yaml-cpp/yaml.h>

class Histogram {
  public:
    int fd;

    YAML::Node histograms;

    struct perf_buffer* pb = nullptr;

    prometheus::Family<prometheus::Histogram>* hists;

    std::vector<int>    sizes;
    std::vector<int>    offsets;
    std::vector<double> bucket;
    std::vector<char*>  bufs;

    std::vector<YAML::Node>  decoders;
    std::vector<std::string> types;
    std::vector<std::string> names;

    Histogram(int, YAML::Node);
    ~Histogram();
    error_t init();
    void    observe();
};

#endif