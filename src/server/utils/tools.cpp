#include "tools.hpp"

std::map<std::string, size_t> size_map = {
    { "u64", sizeof(_u64_m) },
    { "u32", sizeof(_u32_m) },
    { "u8", sizeof(_u8_m) },
    { "int", sizeof(int) },
    { "double", sizeof(double) },
    { "char", sizeof(char) },
    { "short", sizeof(short) },
};

std::map<std::string, TYPES> type_num_map = {
    { "u64", TYPES::E_U64 },
    { "u32", TYPES::E_U32 },
    { "u8", TYPES::E_U8 },
    { "int", TYPES::E_INT },
    { "double", TYPES::E_DOUBLE },
    { "char", TYPES::E_CHAR },
    { "short", TYPES::E_SHORT },
};

bool is_array(const std::string& type) {
    std::string::size_type left  = type.find("[");
    std::string::size_type right = type.find("]");

    if (left != std::string::npos && right != std::string::npos) {
        return true;
    }

    return false;
}

TYPES get_type_num(const std::string& type) {
    if (type_num_map.find(type) != type_num_map.end()) {
        return type_num_map[type];
    }

    if (is_array(type)) return TYPES::E_ARRAY;

    return TYPES::E_UNKNOWN;
}

size_t get_size_by_type(const std::string& type) {
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

double to_double(void* p, TYPES t) {
    switch (t) {
    case TYPES::E_U64:
        return static_cast<double>(*reinterpret_cast<_u64_m*>(p));
    case TYPES::E_U32:
        return static_cast<double>(*reinterpret_cast<_u32_m*>(p));
    case TYPES::E_U8:
        return static_cast<double>(*reinterpret_cast<_u8_m*>(p));
    case TYPES::E_INT:
        return static_cast<double>(*reinterpret_cast<int*>(p));
    case TYPES::E_DOUBLE:
        return static_cast<double>(*reinterpret_cast<double*>(p));
    case TYPES::E_CHAR:
        return static_cast<double>(*reinterpret_cast<short*>(p));
    default:
        throw std::runtime_error("Not support type num: " + std::to_string(t) + ".\n");
    }
}

_u8_m read_u8(void* p, char* buf) {
    memcpy(buf, p, sizeof(_u8_m));
    return *reinterpret_cast<_u8_m*>(buf);
}

_u32_m read_u32(void* p, char* buf) {
    memcpy(buf, p, sizeof(_u32_m));
    return *reinterpret_cast<_u32_m*>(buf);
}

_u64_m read_u64(void* p, char* buf) {
    memcpy(buf, p, sizeof(_u64_m));
    return *reinterpret_cast<_u64_m*>(buf);
}

int read_int(void* p, char* buf) {
    memcpy(buf, p, sizeof(int));
    return *reinterpret_cast<int*>(buf);
}

double read_double(void* p, char* buf) {
    memcpy(buf, p, sizeof(double));
    return *reinterpret_cast<double*>(buf);
}

char read_char(void* p, char* buf) {
    memcpy(buf, p, sizeof(char));
    return *reinterpret_cast<char*>(buf);
}

_u64_m read_data_by_type(char* p, TYPES t, char* buf) {
    _u64_m key = 0;

    switch (t) {
    case TYPES::E_U64:
        key = read_u64(p, buf);
        break;
    case TYPES::E_U32:
        key = read_u32(p, buf);
        break;
    case TYPES::E_U8:
        key = read_u8(p, buf);
        break;
    case TYPES::E_INT:
        key = read_int(p, buf);
        break;
    case TYPES::E_DOUBLE:
        key = read_double(p, buf);
        break;
    case TYPES::E_CHAR:
        key = read_char(p, buf);
        break;
    default:
        break;
    }

    return key;
}

struct Test {
    char a;
    int  b;
};

int alignment() {
    // 如果返回 4, 则说明数据需要以 4 的整数倍对齐
    return offsetof(Test, b);
}