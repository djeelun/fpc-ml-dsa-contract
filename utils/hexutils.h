#pragma once

#include <string>
#include <vector>
#include <stdint.h>
#include <stdio.h>

std::string bytes_to_hex_string(const std::vector<uint8_t> &input);

std::string bytes_to_hex_string(const uint8_t* input, const size_t size);

std::vector<uint8_t> hex_string_to_bytes(const std::string& input);