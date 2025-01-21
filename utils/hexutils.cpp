#include <vector>
#include <string>
#include <stdint.h>
#include <stdio.h>
#include <stdexcept>

// From stackoverflow: https://stackoverflow.com/a/55364414
std::string bytes_to_hex_string(const std::vector<uint8_t> &input)
{
  static const char characters[] = "0123456789ABCDEF";

  // Zeroes out the buffer unnecessarily, can't be avoided for std::string.
  std::string ret(input.size() * 2, 0);
  
  // Hack... Against the rules but avoids copying the whole buffer.
  auto buf = const_cast<char *>(ret.data());
  
  for (const auto &oneInputByte : input)
  {
    *buf++ = characters[oneInputByte >> 4];
    *buf++ = characters[oneInputByte & 0x0F];
  }
  return ret;
}

std::string bytes_to_hex_string(const uint8_t* input, const size_t size)
{
  static const char characters[] = "0123456789ABCDEF";

  // Zeroes out the buffer unnecessarily, can't be avoided for std::string.
  std::string ret(size * 2, 0);
  
  // Hack... Against the rules but avoids copying the whole buffer.
  auto buf = const_cast<char *>(ret.data());
  
  for (size_t i = 0; i < size; ++i)
  {
    *buf++ = characters[input[i] >> 4];
    *buf++ = characters[input[i] & 0x0F];
  }
  return ret;
}

uint8_t hex_to_num(char msb, char lsb) {
    // Validate characters
    auto hex_char_to_int = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::invalid_argument("Invalid hex character");
    };

    return (hex_char_to_int(msb) << 4) | hex_char_to_int(lsb);
}

std::vector<uint8_t> hex_string_to_bytes(const std::string& input) {
    if (input.empty()) {
        throw std::invalid_argument("Input string cannot be empty");
    }

    if (input.size() % 2 != 0) {
        throw std::invalid_argument("Hex string length must be even");
    }

    std::vector<uint8_t> output;
    output.reserve(input.size() / 2); // Reserve memory for efficiency

    for (size_t i = 0; i < input.size(); i += 2) {
        output.push_back(hex_to_num(input[i], input[i + 1]));
    }

    return output;
}