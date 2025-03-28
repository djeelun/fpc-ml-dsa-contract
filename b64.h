#pragma once
#include <string>

const std::string b64encode(const void* data, const size_t &len);
const std::string b64decode(const void* data, const size_t &len);
std::string b64encode(const std::string& str);
std::string b64decode(const std::string& str64);
