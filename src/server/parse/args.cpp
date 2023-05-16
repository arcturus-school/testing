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
    switch (key) {
    case 'v':
        enable_debug = true;
        Log::log("Debug enabled.", "\n");
        break;
    case 'c':
        config_path = arg;
        break;
    case 'e':
        enable_bpf_debug = true;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp_parser = { options, parse_opt, 0, 0 };

error_t parse_args(int argc, char* argv[]) {
    return argp_parse(&argp_parser, argc, argv, 0, nullptr, nullptr);
}