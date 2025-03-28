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

int decodeBase64ToIntArr(const std::string inputB64, int X[XLEN]) {
  std::string decodedStr = b64decode(inputB64);
  if (decodedStr.size() != sizeof(int) * XLEN) return -1;
  std::memcpy(X, decodedStr.data(), sizeof(int) * XLEN);

  return 0;
}

int putCipher(const std::string cipherB64, const std::string cipherId, shim_ctx_ptr_t ctx) {
  if (cipherId.length() == 0) return -1; // cant have empty string as id
  std::string decodedStr = b64decode(cipherB64);
  if (decodedStr.size() != sizeof(int) * BLEN) return -2;
  int cipher[BLEN];
  std::memcpy(cipher, decodedStr.data(), sizeof(int) * BLEN);
  put_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], sizeof(int) * BLEN, ctx);

  return 0;
}

int getCipher(const std::string cipherId, shim_ctx_ptr_t ctx, int cipher[BLEN]) {
  uint32_t resultLen;
  get_public_state(cipherId.c_str(), (uint8_t*)&cipher[0], sizeof(int) * BLEN, &resultLen, ctx);
  if (resultLen == 0) { // key not found
    return -1;
  } 
  if (resultLen != BLEN) { // should never happen
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
  cipherB64 = b64encode(cipherString);
  return 0;
}


// (128*128 + 896 + 896 + 896 + (896 + 896) * (896 + 896 + 896)) * 4 = 19.343.872 = approx 20 Mb
std::string updateCipher(const std::string cipherId, const std::string keySwitchMatB64, const std::string b0primeB64, shim_ctx_ptr_t ctx) {
  int X[XLEN];
  int err = decodeBase64ToIntArr(keySwitchMatB64, X); if (err) return "FAILED TO DECODE";
  int b0prime[BLEN];
  err = decodeBase64ToIntArr(b0primeB64, b0prime); if (err) return "FAILED TO DECODE";

  int b[BLEN];
  err = getCipher(cipherId, ctx, b); if (err) return "FAILED TO RETRIEVE CIPHER";

  int newB[MBAR + 2 * WLEN];

  multVecByMat(&b[0], &X[0], &newB[0], MBAR + WLEN, MBAR); // new b0 is mbar long
  multVecByMat(&b[0], &X[(MBAR + WLEN) * MBAR], &newB[MBAR], MBAR + WLEN, WLEN); // new b1 is wlen long
  multVecByMat(&b[0], &X[(MBAR + WLEN) * WLEN], &newB[MBAR + WLEN], MBAR + WLEN, WLEN);

  addVectors(&b[MBAR + WLEN], &newB[MBAR + WLEN], WLEN);
  addVectors(&b0prime[0], &newB[0], MBAR + 2 * WLEN);

  std::stringstream ss;
  for (int i = 0; i < MBAR + 2 * WLEN; i++) {
    ss << std::to_string(newB[i]) << std::endl;
  }
  return ss.str();
}
