#include "args.hpp"

extern bool enable_debug;

extern bool enable_bpf_debug;

extern std::string config_path;

static const struct argp_option options[] = {
    { "verbose", 'v', 0, 0, "Enable debug" },
    { "ebpf", 'e', 0, 0, "Enable ebpf program debug" },
    { "config", 'c', "FILE", 0, "Specify config file (YAML format)" },
    {},
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    if (key == 'v') {
        enable_debug = true;
        Log::log("Debug enabled.", "\n");
        return 0;
    }

    if (key == 'c') {
        config_path = arg;
        return 0;
    }

    if (key == 'e') {
        enable_bpf_debug = true;
        Log::log("Ebpf debug enabled.", "\n");
        return 0;
    }

    return ARGP_ERR_UNKNOWN;
}

static struct argp argp_parser = { options, parse_opt, 0, 0 };

error_t parse_args(int argc, char* argv[]) {
    return argp_parse(&argp_parser, argc, argv, 0, NULL, NULL);
}