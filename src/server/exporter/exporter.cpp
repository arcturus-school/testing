#include "exporter.hpp"

// 保存所有 metrics 和 object
std::map<std::string, Program> programs;

extern int port;

auto registry = std::make_shared<prometheus::Registry>();

void run_exporter() {
    std::ostringstream oss;

    oss << "127.0.0.1:" << port;

    // create an http server running on port 8080
    prometheus::Exposer exposer{ oss.str() };

    // ask the exposer to scrape the registry on incoming HTTP requests
    exposer.RegisterCollectable(registry);

    std::cout << "Server is running at " << BLUE("http://" + oss.str() + "/metrics\n");
}

error_t open_all_bpf_object() {
    for (auto it = programs.begin(); it != programs.end(); it++) {
        std::string file = "dist/" + it->first + ".bpf.o";

        bpf_object* obj = bpf_object__open(file.c_str());

        if (!obj) {
            Log::error("Failed to open ", it->first, " bpf object.\n");
            close_bpf_object();
            return -1;
        }

        it->second.object = obj;
    }

    return 0;
}

error_t load_all_bpf_object() {
    for (auto it = programs.begin(); it != programs.end(); it++) {
        error_t err = bpf_object__load(it->second.object);

        if (err) {
            Log::error("Failed to load ", it->first, " bpf object.\n");
            close_bpf_object();
            return -1;
        }
    }

    return 0;
}

void close_bpf_object() {
    for (auto it = programs.begin(); it != programs.end(); ++it) {
        if (it->second.object) {
            bpf_object__close(it->second.object);
            Log::log(it->first, "_bpf_object is closed.\n");
        }
    }
}

void attach_all_bpf_program() {
    struct bpf_program* prog;

    for (auto it = programs.begin(); it != programs.end(); it++) {
        bpf_object__for_each_program(prog, it->second.object) {
            bpf_program__attach(prog);
        }
    }
}