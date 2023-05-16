#include "program.hpp"

Program::Program(const YAML::Node& prog) {
    name = prog["name"] ? prog["name"].as<std::string>() : "unknown";

    Log::log("Program ", name);

    if (prog["metrics"]) {
        YAML::Node metrics = prog["metrics"];

        if (metrics["histograms"]) {
            for (size_t i = 0; i < metrics["histograms"].size(); i++) {
                metrics.push_back(Histogram(metrics["histograms"][i]));
            }
        }

        if (metrics["counters"]) {
            for (size_t i = 0; i < metrics["counters"].size(); i++) {
                metrics.push_back(Counter(metrics["counters"][i]));
            }
        }
    }
}

void Program::observe() {
    for (auto it = metrics.begin(); it != metrics.end(); it++) {
        (*it).observe();
    }
}

Program::~Program() {
    if (obj) {
        bpf_object__close(obj);
        Log::log(name, "_bpf_object is closed.\n");
    }
}

error_t Program::load_obj() {
    if (!obj) {
        Log::warn("Object is null, so program ", name, " skips open object.\n");
        return -1;
    }

    error_t err = bpf_object__load(obj);

    if (err) {
        Log::error("Failed to load ", name, " bpf object.\n");
        return err;
    }

    Log::success("Load " + name + " bpf object.\n");

    return 0;
}

error_t Program::open_obj() {
    std::string file = "dist/" + name + ".bpf.o";

    obj = bpf_object__open(file.c_str());

    if (!obj) {
        Log::error("Failed to open ", name, " bpf object.\n");
        return -1;
    }

    Log::success("Open " + name + " bpf object.\n");
}

void Program::attach_obj() {
    if (!obj) {
        Log::warn("Object is null, so program ", name, " skips attachment.\n");
        return;
    }

    struct bpf_program* prog;

    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }
}

error_t Program::init() {
    if (!obj) {
        Log::warn("Bpf object is missing, so ", name, " skips initialization.\n");
        return INIT_FAILED;
    }

    int err;

    for (auto it = metrics.begin(); it != metrics.end(); it++) {
        err = (*it).init(obj);

        if (err) return INIT_FAILED;
    }

    return INIT_SUCCESS;
}