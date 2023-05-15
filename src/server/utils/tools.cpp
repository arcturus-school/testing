#include "tools.hpp"

std::map<std::string, size_t> size_map = {
    { "u64", sizeof(unsigned long long) },
    { "u32", sizeof(unsigned int) },
    { "u8", sizeof(unsigned char) },
    { "int", sizeof(int) },
    { "double", sizeof(double) },
    { "char", sizeof(char) },
};

size_t get_size_by_type(std::string& type) {
    return size_map[type];
}