#include "config.hpp"

void close_bpf_object() {
    for (int i = 0; i < programs.size(); i++) {
        bpf_object__close(programs[i]);
        Log::log(metrics[i]["name"], "_bpf_object is close.\n");
    }
}

error_t read_config() {
    if (!exists(config_path)) {
        Log::error("Config file ", config_path, "does not exist.\n");
        return -1;
    }

    YAML::Node config = YAML::LoadFile(config_path);

    for (int i = 0; i < config.size(); i++) {
        metrics.push_back(config[i]);
    }
}