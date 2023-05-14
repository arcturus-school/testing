#include "args.hpp"
#include <iostream>
#include <stdlib.h>
#include <yaml-cpp/yaml.h>

struct Configs configs = { .debug = false };

void read_config_yml() {
    YAML::Node config = YAML::LoadFile(configs.config_path);

    std::cout << config["person"]["name"] << std::endl;
    std::cout << config["person"]["age"] << std::endl;

    auto address = config["person"]["address"];

    std::cout << address["street"] << std::endl;
    std::cout << address["city"] << std::endl;
    std::cout << address["state"] << std::endl;
    std::cout << address["zip"] << std::endl;

    auto fruits = config["fruits"];

    for (int i = 0; i < fruits.size(); i++) {
        std::cout << fruits[i] << std::endl;
    }

    auto matrix = config["matrix"];

    for (int i = 0; i < matrix.size(); i++) {
        for (int j = 0; j < matrix[i].size(); j++) {
            std::cout << matrix[i][j].as<int>() << " ";
        }

        std::cout << std::endl;
    }
}

int main(int argc, char* argv[]) {
    error_t err = parse_args(argc, argv);

    if (err) {
        return EXIT_FAILURE;
    }

    if (configs.config_path != "") {
        read_config_yml();
    }

    return EXIT_SUCCESS;
}