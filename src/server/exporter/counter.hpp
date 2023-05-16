#ifndef _COUNTER_H
#define _COUNTER_H

#include "../utils/decoder.hpp"
#include "../utils/log.hpp"
#include "../utils/tools.hpp"
#include "metric.hpp"

class Counter : public Metric {
  public:
    prometheus::Family<prometheus::Counter>* count;

    Counter(const YAML::Node&);

    error_t init(bpf_object*);
};

#endif