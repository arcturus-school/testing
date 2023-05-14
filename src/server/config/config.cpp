#include "config.hpp"

// 保存所有 metrics 和 object
std::map<std::string, Program> programs;

extern std::string config_path;

extern int port;

void close_bpf_object() {
    for (auto it = programs.begin(); it != programs.end(); ++it) {
        bpf_object__close(it->second.object);
        Log::log(it->first, "_bpf_object is closed.\n");
    }
}

error_t read_config() {
    if (!exists(config_path)) {
        Log::error("Config file ", config_path, " does not exist.\n");
        return -1;
    }

    YAML::Node config = YAML::LoadFile(config_path);

    auto p = config["programs"];

    if (config["server"] && config["server"]["port"]) {
        port = config["server"]["port"].as<int>();
    }

    for (std::size_t i = 0; i < p.size(); i++) {
        struct Program item = {
            .metrics = p[i]["metrics"],
        };

        programs.insert(std::make_pair(p[i]["name"].as<std::string>(), item));

        Log::log("Read metrics ", p[i]["name"].as<std::string>(), ".\n");
    }

    return 0;
}