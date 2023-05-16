#ifndef _METRIC_H
#define _METRIC_H

#include "../utils/std.hpp"
#include "label.hpp"

extern bool exiting;

class Metric {
  public:
    std::vector<Label> labels;
    std::string        name;
    std::string        help;

    struct perf_buffer* pb = nullptr;

    virtual ~Metric() {
        perf_buffer__free(pb);
    }

    Metric(const YAML::Node& m) {
        name = m["name"] ? m["name"].as<std::string>() : "unknown";
        help = m["description"] ? m["description"].as<std::string>() : "not description";

        if (!m["labels"]) {
            Log::warn("There is not labels in histogram of ", name, ".\n");
            return;
        }

        auto& ls = m["labels"];

        for (size_t i = 0; i < ls.size(); i++) {
            this->labels.push_back(Label(ls[i]));
        }

        int o = alignment(), s;

        // 不超过 4
        o = o > 4 ? 4 : o;

        // 获取各数据偏移量
        this->labels[0].offset = 0;

        for (size_t i = 1; i < this->labels.size(); i++) {
            s = this->labels[i - 1].offset + this->labels[i - 1].size;

            // 考虑到数据对齐问题...
            if (s % o == 0 || (o - s % o) - this->labels[i].size > 0) {
                this->labels[i].offset = s;
            } else {
                this->labels[i].offset = s + (o - s % o);
            }
        }
    }

    virtual void observe() {
        if (!pb) {
            Log::warn(name, " skips observe.\n");
            return;
        }

        int err;

        while (true) {
            err = perf_buffer__poll(pb, 0);

            if (err < 0 && err != -EINTR) {
                fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
                break;
            }

            if (exiting) {
                break;
            }
        }
    }

    virtual error_t init(bpf_object*) {
        Log::log("do nothing...\n");
        return 0;
    }
};

#endif