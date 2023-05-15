#include "config/config.hpp"
#include "exporter/exporter.hpp"
#include "parse/args.hpp"
#include "utils/file.hpp"
#include <signal.h>
#include <stdlib.h>

extern std::string config_path;

extern bool enable_debug;

extern bool enable_bpf_debug;

extern bool exiting;

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
    err = open_all_bpf_object();

    if (err) return EXIT_FAILURE;

    err = load_all_bpf_object();

    if (err) return EXIT_FAILURE;

    attach_all_bpf_program();

    register_all_event_handle();

    run_exporter();

    observe();

    // 一些清理工作
    close_bpf_object();

    return EXIT_SUCCESS;
}