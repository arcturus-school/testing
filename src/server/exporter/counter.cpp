#include "counter.hpp"

extern bool exiting;

extern std::shared_ptr<prometheus::Registry> registry;

Counter::Counter(const YAML::Node& counter) : Metric(counter){};

error_t Counter::init(bpf_object* obj) {
    count = &prometheus::BuildCounter().Name(name).Help(help).Register(*registry);

    auto handle = [](void* ctx, int cpu, void* data, __u32 size) {
        Counter* c = (Counter*)ctx;

        auto& co = c->count->Add(parse_labels(data, c->labels));

        co.Increment();
    };

    auto handle_lost = [](void* ctx, int cpu, _u64_m lost_cnt) {
        Counter* m = (Counter*)ctx;

        Log::error("[In ", m->name, "] lost ", lost_cnt, " events on CPU #", cpu);
    };

    struct perf_buffer_opts opt = {
        .sample_cb = handle,
        .lost_cb   = handle_lost,
        .ctx       = this,
    };

    int fd = bpf_object__find_map_fd_by_name(obj, name.c_str());

    if (fd < 0) {
        Log::warn("There is not map names ", name, ".\n");
        return GET_FD_FAILED;
    }

    Log::success("Obtain file descriptor of map ", name, ".\n");

    pb = perf_buffer__new(fd, 16, &opt);

    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer: %d\n", -errno);

        perf_buffer__free(pb);

        return INIT_PERF_BUFFER_FAILED;
    }

    return INIT_SUCCESS;
}
