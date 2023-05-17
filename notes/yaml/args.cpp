#include "args.hpp"

static const struct argp_option options[] = {
    { "verbose", 'v', 0, 0, "Enable debug" },
    { "config", 'c', "FILE", 0, "Specify config file (YAML format)" },
    {},
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    switch (key) {
    case 'v':
        std::cout << "Debug enabled." << std::endl;
        configs.debug = true;
        break;
    case 'c':
        std::cout << "config path: " << arg << std::endl;
        configs.config_path = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp_parser = { options, parse_opt, 0, 0 };

error_t parse_args(int argc, char* argv[]) {
    std::cout << "args number: " << argc - 1 << std::endl;

    return argp_parse(&argp_parser, argc, argv, 0, NULL, NULL);
}