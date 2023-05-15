#include "histogram.hpp"

extern bool exiting;

extern std::shared_ptr<prometheus::Registry> registry;

// 解析 labels
std::map<std::string, std::string> parse_labels(void* p, Histogram* ctx) {
    std::map<std::string, std::string> map;

    // 忽略第一个值
    for (size_t i = 1; i < ctx->names.size(); i++) {
        std::string        value;
        unsigned long long key = read_data_by_type((char*)p + ctx->offsets[i], ctx->types[i], ctx->bufs[i]);

        if (ctx->decoders[i]["name"]) {
            std::string decoder = ctx->decoders[i]["name"].as<std::string>();

            if (decoder == "static_map") {
                value = static_map(key, ctx->decoders[i]["static_map"]);
            } else if (decoder == "inet") {
                int af;

                auto it = std::find(ctx->names.begin(), ctx->names.end(), "protocol");

                if (it != ctx->names.end()) {
                    int idx = std::distance(ctx->names.begin(), it);

                    af = read_data_by_type((char*)p + ctx->offsets[idx], ctx->types[idx], ctx->bufs[idx]);

                    value = inet(af, (char*)p + ctx->offsets[i]);
                } else {
                    Log::warn("Labels missing `protocol`.");
                    value = std::to_string(key);
                }
            } else {
                Log::error("Not support decoder.\n");
                value = std::to_string(key);
            }
        } else {
            value = std::to_string(key);
        }

        map[ctx->names[i]] = value;
    }

    return map;
}

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

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    Log::error("Lost ", lost_cnt, " events on CPU #", cpu);
}

Histogram::Histogram(int fd, YAML::Node histograms) {
    this->fd         = fd;
    this->histograms = histograms;

    std::vector<YAML::Node> labels = histograms["labels"].as<std::vector<YAML::Node>>();

    for (size_t i = 0; i < labels.size(); i++) {
        types.push_back(labels[i]["type"].as<std::string>());
        names.push_back(labels[i]["name"].as<std::string>());
        decoders.push_back(labels[i]["decoders"]);
    }

    offsets.push_back(0);
    for (size_t i = 1; i < labels.size(); i++) {
        offsets.push_back(offsets[i - 1] + get_size_by_type(types[i - 1]));
    }

    for (size_t i = 0; i < labels.size(); i++) {
        size_t s = get_size_by_type(types[i]);

        sizes.push_back(s);
        bufs.push_back((char*)malloc(s)); // 为每个 label 分配一个缓冲区
    }
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

    hists = &prometheus::BuildHistogram().Name(name).Help(help).Register(*registry);

    bool exp2 = false;

    if (histograms["bucket_type"]) {
        exp2 = histograms["bucket_type"].as<std::string>() == "exp2";
    }

    int min = histograms["bucket_min"] ? histograms["bucket_min"].as<int>() : 0;
    int max = histograms["bucket_max"] ? histograms["bucket_max"].as<int>() : 27;

    bucket = exp2 ? create_exp2_buckets(min, max, 1) : create_linear_buckets(min, max, 1);

    auto handle = [](void* ctx, int cpu, void* data, __u32 size) {
        Histogram* c = (Histogram*)ctx;

        memcpy(c->bufs[0], data, c->sizes[0]);
        double value = convert_data_to_double(c->bufs[0], c->types[0]);

        auto& h = c->hists->Add(parse_labels(data, c), c->bucket);

        h.Observe(value);
    };

    struct perf_buffer_opts opt = {
        .sample_cb = handle,
        .lost_cb   = handle_lost_events,
        .ctx       = this,
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

    for (auto it = bufs.begin(); it != bufs.end(); it++) {
        free(*it);
    }
}