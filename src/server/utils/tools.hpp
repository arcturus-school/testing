#ifndef _TOOLS_H
#define _TOOLS_H

#include <map>
#include <stdexcept>
#include <string>

size_t get_size_by_type(std::string&);

double convert_data_to_double(void* p, const std::string& s);

#endif