#include "config/config.hpp"
#include "parse/args.hpp"
#include "utils/file.hpp"
#include <stdlib.h>

extern std::string config_path;

int main(int argc, char* argv[]) {
    error_t err = parse_args(argc, argv);

    if (err) {
        return EXIT_FAILURE;
    }

    if (config_path.length() != 0) {
        Log::log("Config file: ", get_absolute_path(config_path), ".\n");

        err = read_config();

        if (err) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}