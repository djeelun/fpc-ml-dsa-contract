#include <iostream>
#include <string>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <cstdlib>
#include <sstream>
#include <unistd.h>
#include <sys/syscall.h>
#include "hexutils.h"

void randombytes(uint8_t *out, size_t outlen) {
  static int fd = -1;
  ssize_t ret;

  while(fd == -1) {
    fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1 && errno == EINTR)
      continue;
    else if(fd == -1)
      abort();
  }

  while(outlen > 0) {
    ret = read(fd, out, outlen);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}

void print_num(uint8_t num) {
    std::cout << std::to_string(num) << '\n';
}

bool cmp_arrays(const uint8_t* a, const uint8_t* b, int mlen) {
    // check if input and output are the same
    for (int i = 0; i < mlen; ++i) { // beware hardcoded length
        if (a[i] != b[i]) {
            return false;
        }
    }
    
    return true;
}

void print_int_arr(const uint8_t* arr, int mlen) {
    std::stringstream ss;
    
    for (int i = 0; i < mlen; ++i) {
        ss << std::to_string(arr[i]) << ' ';
    }
    ss << '\n';
    std::cout << ss.str();
}

int main() {
    const int mlen = 59;
    const int ntests = 10000;
    
    uint8_t m[mlen];

    for (int n = 0; n < ntests; ++n) {
        randombytes(m, mlen);
        // print_int_arr(m, mlen);

        std::string med = bytes_to_hex_string(m, mlen);
        // printf(med.data());
        // printf("\n");

        std::vector<uint8_t> output = hex_string_to_bytes(med);
        const uint8_t* outputArr = &output[0];
        // print_int_arr(outputArr, mlen);
        
        if (!cmp_arrays(m, outputArr, mlen)) {
            printf("--- INPUT AND OUTPUT NOT EQUAL: %s ---\n", med.data());
            print_int_arr(m, mlen);
            print_int_arr(outputArr, mlen);
            break;
        }
        
    }
    std::cout << "+++ HEX UTILS TEST SUCCESS +++\n";
    return 0;
}
