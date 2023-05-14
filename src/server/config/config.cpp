#include "config.hpp"

extern std::map<std::string, Program> programs;

extern std::string config_path;

extern int port;

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