#pragma once
#include <string>
#include "shim.h"

#define N 20
#define K 10
#define MBAR 171 // 896 // O(N * K)
#define WLEN (N*K) // 896 // N * K
#define BLEN (MBAR + 2 * WLEN) // MBAR + 2 * WLEN
#define XLEN ((MBAR + WLEN) * (MBAR + 2 * WLEN)) // (MBAR + WLEN) * MBAR + 2 * (MBAR + WLEN) * WLEN
#define Q (1 << K) // 2^K

struct CipherVec {
  int b0[MBAR];
  int b1[WLEN];
  int b2[WLEN];
};

// Ciphertext update function
// keySwitchMat and b0prime are given in base64 encoded string
std::string updateCipher(const std::string cipherId, const std::string tokenB64, shim_ctx_ptr_t ctx);

int getCipher(const std::string cipherId, shim_ctx_ptr_t ctx, std::string &cipherB64);
int putCipher(const std::string cipherB64, const std::string cipherId, shim_ctx_ptr_t ctx);
