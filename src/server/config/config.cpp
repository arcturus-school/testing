#include "config.hpp"

extern std::vector<Program> programs;

extern std::string config_path;

extern int port;

error_t read_config() {
    if (!exists(config_path)) {
        Log::error("Config file ", config_path, " does not exist.\n");
        return CONFIG_MISSING;
    }

    // 加载配置文件
    YAML::Node config = YAML::LoadFile(config_path);

    // 获取端口号
    if (config["server"] && config["server"]["port"]) {
        port = config["server"]["port"].as<int>();
    }

    auto p = config["programs"];

    // 初始化指标程序
    for (size_t i = 0; i < p.size(); i++) {
        programs.push_back(Program(p[i]));
    }

    return 0;
}