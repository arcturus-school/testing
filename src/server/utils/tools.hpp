#ifndef _TOOLS_H
#define _TOOLS_H

#include <cstring>
#include <map>
#include <stdexcept>
#include <string>

size_t get_size_by_type(std::string&);

double convert_data_to_double(void* p, const std::string& s);

unsigned short read_u8(void* p, char* buf);

unsigned int read_u32(void* p, char* buf);

unsigned long long read_u64(void* p, char* buf);

#endif