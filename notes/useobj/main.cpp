#include <bpf/libbpf.h>
#include <iostream>
#include <stdlib.h>

bool debug = true;

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG && !debug) return 0;

    return vfprintf(stderr, format, args);
}

int main() {
    libbpf_set_print(libbpf_print_fn);

    bpf_object* obj = bpf_object__open("hello.bpf.o");

    if (!obj) {
        std::cerr << "Failed to open bpf object." << std::endl;

        return EXIT_FAILURE;
    }

    int err = bpf_object__load(obj);

    if (err) {
        std::cerr << "Failed to load bpf object." << std::endl;

        bpf_object__close(obj);

        return EXIT_FAILURE;
    }

    struct bpf_program* prog;

    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }

    for (int i = 0; i < 6; i++) {
        fprintf(stderr, ".");
    }

    std::cout << std::endl;

    bpf_object__close(obj);

    return EXIT_SUCCESS;
}