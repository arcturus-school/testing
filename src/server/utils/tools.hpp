#ifndef _TOOLS_H
#define _TOOLS_H

#include "log.hpp"

enum TYPES {
    E_U64,
    E_U32,
    E_U8,
    E_INT,
    E_DOUBLE,
    E_CHAR,
    E_UNKNOWN,
    E_ARRAY,
    E_SHORT,
};

TYPES get_type_num(const std::string&);

size_t get_size_by_type(const std::string&);

double to_double(void*, TYPES);

_u8_m read_u8(void*, char*);

_u32_m read_u32(void*, char*);

_u64_m read_u64(void*, char*);

int read_int(void*, char*);

double read_double(void*, char*);

char read_char(void*, char*);

_u64_m read_data_by_type(char*, TYPES, char*);

// 简单获取平台数据对齐方式
int alignment();

#endif