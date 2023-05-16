#include "config/config.hpp"
#include "exporter/exporter.hpp"
#include "parse/args.hpp"
#include "utils/file.hpp"
#include <signal.h>
#include <stdlib.h>

auto registry = std::make_shared<prometheus::Registry>();

extern std::string config_path;

extern bool enable_debug;

extern bool enable_bpf_debug;

extern bool exiting;

extern int port;

static void sig_handler(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG && !enable_bpf_debug) return 0;

    return vfprintf(stderr, format, args);
}

int main(int argc, char* argv[]) {
    error_t err = parse_args(argc, argv);

    if (err) return EXIT_FAILURE;

    libbpf_set_print(libbpf_print_fn);

    if (config_path.length() == 0) {
        Log::error("Config file is missing.\n");
        return EXIT_FAILURE;
    }

    Log::log("Config file: ", get_absolute_path(config_path), ".\n");

    err = read_config();

    if (err) return EXIT_FAILURE;

    // 接收中断请求 ( ctrl + c )
    signal(SIGINT, sig_handler);

    // 加载 bpf 程序
    err = open_all_bpf_objects();

    if (err) return EXIT_FAILURE;

    err = load_all_bpf_objects();

    if (err) return EXIT_FAILURE;

    attach_all_bpf_programs();

    err = register_all_event_handles();

    if (err) return EXIT_FAILURE;

    std::ostringstream oss;

    oss << "127.0.0.1:" << port;

    // create an http server running on port 8080
    prometheus::Exposer exposer{ oss.str() };

    // ask the exposer to scrape the registry on incoming HTTP requests
    exposer.RegisterCollectable(registry);

    std::cout << "Server is running at " << BLUE("http://" + oss.str() + "/metrics\n");

    observe();

    return EXIT_SUCCESS;
}