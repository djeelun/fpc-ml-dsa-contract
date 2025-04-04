#include "tdue.h"
#include "shim.h"
#include <string>
#include <sstream>
#include "b64.h"

void multVecByMat(const int *b, const int *mat, int *bres, const int bLen, const int matCols) {
  for (int i = 0; i < matCols; ++i) {
    bres[i] = 0;
    for (int j = 0; j < bLen; ++j) {
      bres[i] += b[j] * mat[i * bLen + j];
    }
  }
}
void addVectors(const int *a, int *b, const int vecLen) {
  for (int i = 0; i < vecLen; ++i) {
    b[i] += a[i];
  }
}

void modArray(int arr[BLEN], const int mod) {
  for (int i = 0; i < BLEN; ++i) {
    arr[i] = arr[i] % mod;
  }
}

int decodeBase64ToIntArr(const std::string inputB64, int *arr, size_t numElems) {
  std::string decodedStr = b64decode(inputB64);
  if (decodedStr.size() != sizeof(int) * numElems) return -1;
  std::memcpy(arr, decodedStr.data(), sizeof(int) * numElems);

  return 0;
}

int putCipher(const int cipher[BLEN], const std::string cipherId, shim_ctx_ptr_t ctx) {
  if (cipherId.length() == 0) return -1; // cant have empty string as id
  put_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], sizeof(int) * BLEN, ctx);

  return 0;
}

int putCipher(const std::string cipherB64, const std::string cipherId, shim_ctx_ptr_t ctx) {
  if (cipherId.length() == 0) return -1; // cant have empty string as id
  std::string decodedStr = b64decode(cipherB64);
  if (decodedStr.size() != sizeof(int) * BLEN) return -2;
  int cipher[BLEN];
  std::memcpy(&cipher[0], decodedStr.data(), sizeof(int) * BLEN);
  put_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], sizeof(int) * BLEN, ctx);

  return 0;
}

int getCipher(const std::string cipherId, shim_ctx_ptr_t ctx, int cipher[BLEN]) {
  uint32_t resultLen;
  get_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], sizeof(int) * BLEN, &resultLen, ctx);
  if (resultLen == 0) { // key not found
    return -1;
  } 
  if (resultLen != sizeof(int) * BLEN) { // should never happen
    return -2;
  }
  return 0;
}

int getCipher(const std::string cipherId, shim_ctx_ptr_t ctx, std::string &cipherB64) {
  int cipher[BLEN];
  uint32_t resultLen;
  get_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], sizeof(int) * BLEN, &resultLen, ctx);
  if (resultLen == 0) { // key not found
    return -1;
  } 
  if (resultLen != sizeof(int) * BLEN) { // should never happen
    return -2;
  }
  std::string cipherString(sizeof(int) * BLEN, '\0');
  std::memcpy(cipherString.data(), &cipher[0], sizeof(int) * BLEN); // Copy bytes
  cipherB64 = b64encode(cipherString);
  return 0;
}


// (128*128 + 896 + 896 + 896 + (896 + 896) * (896 + 896 + 896)) * 4 = 19.343.872 = approx 20 Mb
std::string updateCipher(const std::string cipherId, const std::string keySwitchMatB64, const std::string b0primeB64, shim_ctx_ptr_t ctx) {
  int X[XLEN];
  int err = decodeBase64ToIntArr(keySwitchMatB64, &X[0], XLEN); if (err) return "FAILED TO DECODE KEYSWITCHMAT";
  int b0prime[BLEN];
  err = decodeBase64ToIntArr(b0primeB64, &b0prime[0], BLEN); if (err) return "FAILED TO DECODE B0PRIME";

  int b[BLEN];
  err = getCipher(cipherId, ctx, b); if (err) return "FAILED TO RETRIEVE CIPHER";

  int newB[BLEN];

  // b' = b * M + b0'
  // where M is [[X00, X01, X02], [X10, X11, X12], [0, 0, I]]
  // b *M could be rewritten as 
  // b'0 = b0 * X00 + b1 * X10;
  // b'1 = b0 * X10 + b1 * X11
  // b'2 = b0 * X20 + b1 * X21 + b2;
  multVecByMat(&b[0], &X[0], &newB[0], MBAR + WLEN, MBAR); // b'0 = b0,1 * X0
  multVecByMat(&b[0], &X[(MBAR + WLEN) * MBAR], &newB[MBAR], MBAR + WLEN, WLEN); // b'1 = b0,1 * X1
  multVecByMat(&b[0], &X[(MBAR + WLEN) * (MBAR + WLEN)], &newB[MBAR + WLEN], MBAR + WLEN, WLEN); // b'2 = b0,1 * X2
  addVectors(&b[MBAR + WLEN], &newB[MBAR + WLEN], WLEN); // b'2 += b2

  // b' += b0'
  addVectors(&b0prime[0], &newB[0], MBAR + 2 * WLEN);

  // modulo q
  modArray(newB, Q);

  // update cipher on ledger
  err = putCipher(newB, cipherId, ctx); if (err) return "FAILED TO UPLOAD CIPHER";

  return "SUCCESS: UPDATED CIPHERTEXT";
}
