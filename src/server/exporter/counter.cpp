#include "counter.hpp"

extern bool exiting;

extern std::shared_ptr<prometheus::Registry> registry;

// 解析 labels
std::map<std::string, std::string> parse_labels(void* p, Counter* ctx) {
    std::map<std::string, std::string> map;

    for (size_t i = 0; i < ctx->names.size(); i++) {
        std::string        value;
        unsigned long long key = read_data_by_type((char*)p + ctx->offsets[i], ctx->types[i], ctx->bufs[i]);
        std::cout << "key: " << key << " " << ctx->types[i] << " " << ctx->offsets[i] << " " << ctx->sizes[i] << std::endl;

        if (ctx->decoders[i]["name"]) {
            std::string decoder = ctx->decoders[i]["name"].as<std::string>();

            if (decoder == "static_map") {
                value = static_map(key, ctx->decoders[i]["static_map"]);
                std::cout << "value: " << value << std::endl;

            } else if (decoder == "inet") {
                auto it = std::find(ctx->names.begin(), ctx->names.end(), "protocol");

                if (it != ctx->names.end()) {
                    int idx = std::distance(ctx->names.begin(), it);
                        
                    int af = read_data_by_type((char*)p + ctx->offsets[idx], ctx->types[idx], ctx->bufs[idx]);
                    std::cout << "af: " << af << " " << idx << std::endl;

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

Counter::Counter(int fd, const YAML::Node& counter) {
    this->fd      = fd;
    this->counter = counter;

    std::vector<YAML::Node> labels = counter["labels"].as<std::vector<YAML::Node>>();

    for (size_t i = 0; i < labels.size(); i++) {
        types.push_back(labels[i]["type"].as<std::string>());
        names.push_back(labels[i]["name"].as<std::string>());
        decoders.push_back(labels[i]["decoder"]);
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

void Counter::observe() {
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

error_t Counter::init() {
    std::string name = counter["name"].as<std::string>();
    std::string help = counter["description"].as<std::string>();

    count = &prometheus::BuildCounter().Name(name).Help(help).Register(*registry);

    auto handle = [](void* ctx, int cpu, void* data, __u32 size) {
        Counter* c = (Counter*)ctx;

        auto& co = c->count->Add(parse_labels(data, c));

        co.Increment();
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

Counter::~Counter() {
    perf_buffer__free(pb);

    for (auto it = bufs.begin(); it != bufs.end(); it++) {
        free(*it);
    }
}