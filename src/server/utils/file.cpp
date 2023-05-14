#include "file.hpp"

std::string current_path() {
    std::filesystem::path cwd = std::filesystem::current_path();

    return cwd.string();
}

std::string get_absolute_path(const std::string& file) {
    std::filesystem::path path = std::filesystem::absolute(file);

    return path.string();
}

bool exists(const std::string& file) {
    if (std::filesystem::exists(file)) {
        return true;
    }

    return false;
}