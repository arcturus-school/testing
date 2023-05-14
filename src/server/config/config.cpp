#include "config.hpp"

// 保存所有 metrics 的配置
std::vector<Program> programs;

// 保存所有 ebpf 程序
std::vector<bpf_object*> objects;

extern std::string config_path;

extern int port;

void close_bpf_object() {
    for (std::size_t i = 0; i < objects.size(); i++) {
        bpf_object__close(objects[i]);
        Log::log(programs[i].name, "_bpf_object is closed.\n");
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
            .name    = p[i]["name"].as<std::string>(),
            .metrics = p[i]["metrics"],
        };

        Log::log("Read metrics ", p[i]["name"].as<std::string>(), ".\n");

        programs.push_back(item);
    }

    return 0;
}