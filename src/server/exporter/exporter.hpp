#ifndef _EXPORTER_H
#define _EXPORTER_H

#include "program.hpp"

// 打开所有 ebpf 对象
error_t open_all_bpf_objects();

// 加载全部 ebpf 对象
error_t load_all_bpf_objects();

// 对所有程序进行插桩
void attach_all_bpf_programs();

// 初始化监听事件
error_t register_all_event_handles();

// 运行所有监听事件
void observe();

#endif