#include "args.hpp"

static const struct argp_option options[] = {
    { "verbose", 'v', 0, 0, "Enable debug" },
    { "config", 'c', "FILE", 0, "Specify config file (YAML format)" },
    {},
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    if (key == 'v') {
        Log::log("Debug enabled.", "\n");
        configs.debug = true;
        return 0;
    }

    if (key == 'c') {
        Log::log("config path: ", arg, "\n");
        configs.config_path = arg;
        return 0;
    }

    return ARGP_ERR_UNKNOWN;
}

static struct argp argp_parser = { options, parse_opt, 0, 0 };

error_t parse_args(int argc, char* argv[]) {
    Log::log("args number: ", argc - 1);
    return argp_parse(&argp_parser, argc, argv, 0, NULL, NULL);
}