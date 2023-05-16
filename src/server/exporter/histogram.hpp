#ifndef _HISTOGRAM_H
#define _HISTOGRAM_H

#include "metric.hpp"

class Histogram : public Metric {
  public:
    bool exp2 = false;

    prometheus::Family<prometheus::Histogram>* hists;

    std::vector<double> bucket;

    Histogram(const YAML::Node&);

    error_t init(bpf_object*);
};

#endif