#include "shim.h"
#include "verification.h"
#include "hexutils.h"
#include <string>
extern "C" {
    #include "api.h"
}

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
