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

void modArray(int *arr, size_t arrLen, const int mod) {
  for (int i = 0; i < arrLen; ++i) {
    arr[i] = arr[i] % mod;
  }
}

int decodeBase64ToIntArr(const std::string inputB64, int *arr, size_t numElems) {
  std::string decodedStr = b64decode(inputB64);
  if (decodedStr.size() != sizeof(int) * numElems) return -1;
  std::memcpy(arr, decodedStr.data(), sizeof(int) * numElems);

  return 0;
}

int putCipher(const int *cipher, const size_t cipherLen, const std::string cipherId, shim_ctx_ptr_t ctx) {
  if (cipherId.length() == 0) return -1; // cant have empty string as id
  put_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], cipherLen, ctx);

  return 0;
}

int putCipher(const std::string cipherB64, const std::string cipherId, shim_ctx_ptr_t ctx) {
  if (cipherId.length() == 0) return -1; // cant have empty string as id
  std::string decodedStr = b64decode(cipherB64);
  if (decodedStr.size() != sizeof(int) * BLEN) return -2;
  int *cipher = (int *)malloc(sizeof(int) * BLEN);
  if (cipher == NULL) return -3;
  std::memcpy(&cipher[0], decodedStr.data(), sizeof(int) * BLEN);
  put_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], sizeof(int) * BLEN, ctx);
  free(cipher);

  return 0;
}

int getCipher(const std::string cipherId, shim_ctx_ptr_t ctx, int *cipher, const size_t cipherLen) {
  uint32_t resultLen;
  get_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], cipherLen, &resultLen, ctx);
  if (resultLen == 0) { // key not found
    return -1;
  } 
  if (resultLen != sizeof(int) * BLEN) { // should never happen
    return -2;
  }
  return 0;
}

int getCipher(const std::string cipherId, shim_ctx_ptr_t ctx, std::string &cipherB64) {
  int *cipher = (int *)malloc(sizeof(int) * BLEN);
  if (cipher == NULL) return -3;
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
  free(cipher);
  cipherB64 = b64encode(cipherString);
  return 0;
}


// (128*128 + 896 + 896 + 896 + (896 + 896) * (896 + 896 + 896)) * 4 = 19.343.872 = approx 20 Mb
std::string updateCipher(const std::string cipherId, const std::string tokenB64, shim_ctx_ptr_t ctx) {
  int *token = (int *)malloc(sizeof(int) * (XLEN + BLEN));
  if (token == NULL) return "Error: couldn't malloc for token";
  int err = decodeBase64ToIntArr(tokenB64, &token[0], XLEN + BLEN); if (err) return "FAILED TO DECODE TOKEN";

  int *X = token;
  int *b0prime = token + XLEN;

  int *b = (int *)malloc(sizeof(int) * BLEN);
  if (X == NULL) return "Error: couldn't malloc for b";
  err = getCipher(cipherId, ctx, b, sizeof(int) * BLEN); if (err) return "FAILED TO RETRIEVE CIPHER";

  int *newB = (int *)malloc(sizeof(int) * BLEN);
  if (X == NULL) return "Error: couldn't malloc for newB";

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
  free(b);

  // b' += b0'
  addVectors(&b0prime[0], &newB[0], MBAR + 2 * WLEN);
  free(token);

  // modulo q
  modArray(newB, BLEN, Q);

  // update cipher on ledger
  err = putCipher(newB, sizeof(int) * BLEN, cipherId, ctx); if (err) return "FAILED TO UPLOAD CIPHER";
  free(newB);

  return "SUCCESS: UPDATED CIPHERTEXT";
}
