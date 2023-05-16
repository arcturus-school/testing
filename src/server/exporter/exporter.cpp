#include "exporter.hpp"

std::vector<Program>     programs;
std::vector<std::thread> ts; // 记录每个 metric 的监听线程

error_t open_all_bpf_objects() {
    int err;

    for (auto it = programs.begin(); it != programs.end(); it++) {
        err = (*it).open_obj();

        if (err) return err;
    }

    return 0;
}

error_t load_all_bpf_objects() {
    int err;

    for (auto it = programs.begin(); it != programs.end(); it++) {
        err = (*it).load_obj();

        if (err) return err;
    }

    return 0;
}

void attach_all_bpf_programs() {
    for (auto it = programs.begin(); it != programs.end(); it++) {
        (*it).attach_obj();
    }
}

error_t register_all_event_handles() {
    error_t err;

    for (auto it = programs.begin(); it != programs.end(); it++) {
        err = (*it).init();

        if (err) return err;
    }

    return 0;
}

void observe() {
    for (auto it = programs.begin(); it != programs.end(); it++) {
        (*it).observe();
    }

    for (auto it = ts.begin(); it != ts.end(); it++) {
        (*it).join();
    }
}