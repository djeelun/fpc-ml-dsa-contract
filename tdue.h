#pragma once
#include <string>
#include "shim.h"

#define N 2
#define K 5
#define MBAR 10 // 896 // O(N * K)
#define WLEN 10 // 896 // N * K
#define BLEN 30 // MBAR + 2 * WLEN
#define XLEN 600 // (MBAR + WLEN) * MBAR + 2 * (MBAR + WLEN) * WLEN
#define Q 32 // 2^K

struct CipherVec {
  int b0[MBAR];
  int b1[WLEN];
  int b2[WLEN];
};

// Ciphertext update function
// keySwitchMat and b0prime are given in base64 encoded string
std::string updateCipher(const std::string cipherId, const std::string keySwitchMatB64, const std::string b0primeB64, shim_ctx_ptr_t ctx);

int getCipher(const std::string cipherId, shim_ctx_ptr_t ctx, int cipher[BLEN]);
int putCipher(const std::string cipherB64, const std::string cipherId, shim_ctx_ptr_t ctx);
