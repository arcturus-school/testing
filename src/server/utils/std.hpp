#include <argp.h>
#include <arpa/inet.h>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// thrid-part lib
#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>
#include <yaml-cpp/yaml.h>

// libbpf
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// macro
#define INIT_FAILED -1
#define INIT_PERF_BUFFER_FAILED -2
#define GET_FD_FAILED -3
#define CONFIG_MISSING -4
#define INIT_SUCCESS 0

// type
typedef unsigned long long _u64_m;
typedef unsigned int       _u32_m;
typedef unsigned char      _u8_m;