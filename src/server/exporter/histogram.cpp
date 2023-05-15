#include "histogram.hpp"

extern bool exiting;

extern std::shared_ptr<prometheus::Registry> registry;

std::vector<double> create_linear_buckets(std::int64_t start, std::int64_t end, std::int64_t step) {
    std::vector<double> bucket;

    for (auto i = start; i < end; i += step) {
        bucket.push_back(i);
    }

    return bucket;
}

std::vector<double> create_exp2_buckets(std::int64_t start, std::int64_t end, std::int64_t step) {
    std::vector<double> bucket;

    for (auto i = start; i < end; i += step) {
        bucket.push_back(pow(2, i));
    }

    return bucket;
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    Log::error("Lost ", lost_cnt, " events on CPU #", cpu);
}

Histogram::Histogram(int fd, YAML::Node histograms) {
    this->fd         = fd;
    this->histograms = histograms;
};

void Histogram::observe() {
    int err;

    while (true) {
        err = perf_buffer__poll(pb, 100);

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }

        if (exiting) {
            break;
        }
    }
}

error_t Histogram::init() {
    std::string name = histograms["name"].as<std::string>();
    std::string help = histograms["description"].as<std::string>();

    auto& hists = prometheus::BuildHistogram().Name(name).Help(help).Register(*registry);

    bool exp2 = false;

    if (histograms["bucket_type"]) {
        exp2 = histograms["bucket_type"].as<std::string>() == "exp2";
    }

    int min = histograms["bucket_min"] ? histograms["bucket_min"].as<int>() : 0;
    int max = histograms["bucket_max"] ? histograms["bucket_max"].as<int>() : 27;

    std::vector<double> bucket = exp2 ? create_exp2_buckets(min, max, 1) : create_linear_buckets(min, max, 1);

    std::vector<YAML::Node> labels = histograms["labels"].as<std::vector<YAML::Node>>();

    std::vector<int> offsets = { 0 };

    for (size_t i = 1; i < labels.size(); i++) {
        std::string type = labels[i - 1]["type"].as<std::string>();
        offsets.push_back(offsets[i - 1] + get_size_by_type(type));
    }

    auto& h = hists.Add({}, bucket);

    auto handle = [](void* ctx, int cpu, void* data, __u32 size) {
        ((prometheus::Histogram*)ctx)->Observe(*reinterpret_cast<unsigned long long*>(data));
    };

    struct perf_buffer_opts opt = {
        .sample_cb = handle,
        .lost_cb   = handle_lost_events,
        .ctx       = &h,
    };

    pb = perf_buffer__new(fd, 16, &opt);

    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer: %d\n", -errno);

        perf_buffer__free(pb);

        return -1;
    }

    return 0;
}

Histogram::~Histogram() {
    perf_buffer__free(pb);
}