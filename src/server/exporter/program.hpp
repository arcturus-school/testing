#ifndef _PROGRAM_H
#define _PROGRAM_H

#include "../utils/log.hpp"
#include "counter.hpp"
#include "histogram.hpp"
#include "metric.hpp"

class Program {
  public:
    std::string name;

    bpf_object* obj = nullptr;

    std::vector<Metric*> metrics;

    Program(const YAML::Node&);

    ~Program();

    void observe();

    error_t init();

    error_t load_obj();

    error_t open_obj();

    void attach_obj();
};

#endif