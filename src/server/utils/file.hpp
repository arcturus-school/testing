#pragma once

#include <filesystem>
#include <string>

// 获取绝对路径
std::string get_absolute_path(std::string& file);

// 判断文件是否存在
bool exists(const std::string& file);

// 获取当前工作目录
std::string current_path();