#include "histogram.hpp"

extern bool exiting;

extern std::shared_ptr<prometheus::Registry> registry;

// 生成线性的桶
std::vector<double> create_linear_buckets(std::int64_t start, std::int64_t end, std::int64_t step) {
    std::vector<double> bucket;

    for (auto i = start; i < end; i += step) {
        bucket.push_back(i);
    }

    return bucket;
}

// 生成 2 次方间隔的桶
std::vector<double> create_exp2_buckets(std::int64_t start, std::int64_t end, std::int64_t step) {
    std::vector<double> bucket;

    for (auto i = start; i < end; i += step) {
        bucket.push_back(pow(2, i));
    }

    return bucket;
}

Histogram::Histogram(const YAML::Node& histogram) : Metric(histogram) {
    if (histogram["bucket_type"]) {
        exp2 = histogram["bucket_type"].as<std::string>() == "exp2";
    }

    int min = histogram["bucket_min"] ? histogram["bucket_min"].as<int>() : 0;
    int max = histogram["bucket_max"] ? histogram["bucket_max"].as<int>() : 27;

    bucket = exp2 ? create_exp2_buckets(min, max, 1) : create_linear_buckets(min, max, 1);
};

error_t Histogram::init(bpf_object* obj) {
    hists = &prometheus::BuildHistogram().Name(name).Help(help).Register(*registry);

    auto handle = [](void* ctx, int cpu, void* data, __u32 size) {
        Histogram* c = (Histogram*)ctx;

        memcpy(c->labels[0].buffer, data, c->labels[0].size);

        double value = to_double(c->labels[0].buffer, c->labels[0].type_num);

        auto& h = c->hists->Add(parse_labels(data, c->labels, 1), c->bucket);

        h.Observe(value);
    };

    auto handle_lost = [](void* ctx, int cpu, _u64_m lost_cnt) {
        Histogram* m = (Histogram*)ctx;

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
