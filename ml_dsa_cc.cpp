#include "shim.h"
#include "logging.h"
#include "hexutils.h"
#include <string>
#include <sstream>
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <numeric>
extern "C" {
    #include "api.h"
}

#define OK "OK"
#define VERIFICATION_SUCCESS "SUCCESS: SIGNATURE IS VALID"
#define VERIFICATION_FAILURE "FAILURE: SIGNATURE IS NOT VALID"
#define KEY_NOT_FOUND "KEY NOT FOUND"

// Verify signature given public key, message, and signature
// Arguments are given as hex strings
int verifySig(std::string _sig, std::string _m, std::string _ctx, std::string _pk, std::string _ml_dsa_version)
{
    LOG_DEBUG("ML_DSA_CC: +++ verifySig +++");
    
    std::vector<uint8_t> sig = hex_string_to_bytes(_sig); // from hexutils.h
    const uint8_t* sigArr = &sig[0];
 
    std::vector<uint8_t> m = hex_string_to_bytes(_m);
    const uint8_t* mArr = &m[0];

    std::vector<uint8_t> pk = hex_string_to_bytes(_pk);
    const uint8_t* pkArr = &pk[0];

    if (_ctx.empty()) {
        if (_ml_dsa_version == "3") {
    	      return pqcrystals_dilithium3_ref_verify(sigArr, sig.size(), mArr, m.size(), NULL, 0, pkArr);
        } else if (_ml_dsa_version == "5") {
    	      return pqcrystals_dilithium5_ref_verify(sigArr, sig.size(), mArr, m.size(), NULL, 0, pkArr);
        } else {
    	      return pqcrystals_dilithium2_ref_verify(sigArr, sig.size(), mArr, m.size(), NULL, 0, pkArr);
        }
    }

    std::vector<uint8_t> ctx = hex_string_to_bytes(_ctx);
    uint8_t* ctxArr = &ctx[0];

    if (_ml_dsa_version == "3") {
        return pqcrystals_dilithium3_ref_verify(sigArr, sig.size(), mArr, m.size(), ctxArr, ctx.size(), pkArr);
    } else if (_ml_dsa_version == "5") {
        return pqcrystals_dilithium5_ref_verify(sigArr, sig.size(), mArr, m.size(), ctxArr, ctx.size(), pkArr);
    } else {
        return pqcrystals_dilithium2_ref_verify(sigArr, sig.size(), mArr, m.size(), ctxArr, ctx.size(), pkArr);
    }
}

// Store verification result publicly on the ledger
// Entry is defined as (key:value)->(signature:result)
std::string putVerificationResult(std::string sig, bool verificationResult, shim_ctx_ptr_t ctx) {
    put_public_state(sig.c_str(), (uint8_t*)&verificationResult, sizeof(verificationResult), ctx);
    return OK;
}

std::string getVerificationResult(std::string sig, shim_ctx_ptr_t ctx) {
    bool verificationResult;
    uint32_t verificationResultLen;
    get_public_state(sig.c_str(), (uint8_t*)&verificationResult, sizeof(verificationResult), &verificationResultLen, ctx);
    if (verificationResultLen == 0) {
        return KEY_NOT_FOUND;
    }
    if (!verificationResult) {
        return VERIFICATION_FAILURE;
    }
    
    return VERIFICATION_SUCCESS;
}

// implements chaincode logic for invoke
int invoke(
    uint8_t* response,
    uint32_t max_response_len,
    uint32_t* actual_response_len,
    shim_ctx_ptr_t ctx)
{
    LOG_DEBUG("ML_DSA_CC: +++ Executing ML-DSA chaincode invocation +++");

    std::string function_name;
    std::vector<std::string> params; // sig, msg, ctx, pk, ml_dsa_version (respectively)
    get_func_and_params(function_name, params, ctx);
    std::string result;

    if (function_name == "verifySig")
    {
        const int is_valid = verifySig(params[0], params[1], params[2], params[3], params[4]);
        result = is_valid ? VERIFICATION_FAILURE : VERIFICATION_SUCCESS;
    }
    else if (function_name == "putVerificationResult") {
        const int is_valid = verifySig(params[0], params[1], params[2], params[3], params[4]);
        const bool verificationResult = (is_valid == 0);

        result = putVerificationResult(params[0], verificationResult, ctx);
    }
    else if (function_name == "getVerificationResult") {
        result = getVerificationResult(params[0], ctx);
    }
    else
    {
        // unknown function
        LOG_DEBUG("ML_DSA_CC: RECEIVED UNKNOWN transaction '%s'", function_name);
        return -1;
    }

    // check that result fits into response
    int neededSize = result.size();
    if (max_response_len < neededSize)
    {
        // error:  buffer too small for the response to be sent
        LOG_DEBUG("ML_DSA_CC: Response buffer too small");
        *actual_response_len = 0;
        return -1;
    }

    // copy result to response
    memcpy(response, result.c_str(), neededSize);
    *actual_response_len = neededSize;
    LOG_DEBUG("ML_DSA_CC: Response: %s", result.c_str());
    LOG_DEBUG("ML_DSA_CC: +++ Executing done +++");
    return 0;
}
