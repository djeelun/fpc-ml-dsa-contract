#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"
#include "sgx_trts.h" // For sgx_read_rand

// COMPROMISES ON MULTI-PLATFORM COMPATIBILTIY, NOW ONLY RESPECTS LINUX

void randombytes(uint8_t *out, size_t outlen) {
  sgx_status_t status;

    while (outlen > 0) {
        // Generate random bytes securely within the enclave
        status = sgx_read_rand(out, outlen);
        if (status != SGX_SUCCESS) {
            // Handle errors: you can log or exit based on your application's needs
            abort();
        }

        // Advance pointer and reduce the remaining length
        outlen = 0; // All bytes are generated in one call
    }
}
