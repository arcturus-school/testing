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
    if (size_map.find(type) != size_map.end()) {
        return size_map[type];
    }

    std::string::size_type left_bracket_pos  = type.find("[");
    std::string::size_type right_bracket_pos = type.find("]");

    if (left_bracket_pos != std::string::npos && right_bracket_pos != std::string::npos) {
        std::string t = type.substr(0, left_bracket_pos);
        std::string s = type.substr(left_bracket_pos + 1, right_bracket_pos - left_bracket_pos - 1);

        if (size_map.find(t) != size_map.end()) {
            return std::stoi(s) * size_map[t];
        }
    }

    throw std::runtime_error("Not support type: " + type + ".\n");
}