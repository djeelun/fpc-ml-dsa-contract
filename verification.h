#pragma once

// some status definitions
#define OK "OK"
#define VERIFICATION_SUCCESS "SUCCESS: SIGNATURE IS VALID"
#define VERIFICATION_FAILURE "FAILURE: SIGNATURE IS NOT VALID"
#define KEY_NOT_FOUND "KEY NOT FOUND"

int verifySig(std::string _sig, std::string _m, std::string _ctx, std::string _pk, std::string _ml_dsa_version);
std::string putVerificationResult(std::string sig, bool verificationResult, shim_ctx_ptr_t ctx);
std::string getVerificationResult(std::string sig, shim_ctx_ptr_t ctx);
