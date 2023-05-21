#ifndef _METRIC_H
#define _METRIC_H

#include "../utils/std.hpp"
#include "label.hpp"

extern bool exiting;

extern std::vector<std::thread> ts;

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

            // 这里存在一个 unsigned int 与 int 直接相减一定为正的问题...
            // 所以隐式转换一下
            int size = this->labels[i].size;

            // 考虑到数据对齐问题...
            if (s % o == 0 || (o - s % o) - size > 0) {
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

        ts.push_back(std::thread(
            [](bool* exiting, Metric* ctx) {
                int err;

                while (true) {
                    // -1 represents waiting indefinitely util event arrives,
                    // which cause ctrl + c not to exit immediately, so we set 1000ms
                    // even though it still may not exit immediately.
                    err = perf_buffer__poll(ctx->pb, 1000);

                    if (err < 0 && err != -EINTR) {
                        fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
                        break;
                    }

                    if (*exiting) {
                        break;
                    }
                }
            },
            &exiting, this));
    }

    virtual error_t init(bpf_object*) {
        Log::log("do nothing...\n");
        return 0;
    }
};

#endif
