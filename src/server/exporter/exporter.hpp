#ifndef _EXPORTER_H
#define _EXPORTER_H

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>

#include "../config/config.hpp"
#include "../utils/log.hpp"
#include <map>
#include <sstream>
#include <string>

void run_exporter();

error_t open_all_bpf_object();

error_t load_all_bpf_object();

// 关闭所有 ebpf obj
void close_bpf_object();

#endif