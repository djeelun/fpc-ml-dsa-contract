#include "shim.h"
#include "verification.h"
#include "b64.h"
#include <string>
extern "C" {
    #include "api.h"
}

// Verify signature given public key, message, and signature
// Arguments are given as base64 encoded strings
int verifySig(std::string _sig, std::string _m, std::string _ctx, std::string _pk, std::string _ml_dsa_version)
{
    LOG_DEBUG("ML_DSA_CC: +++ verifySig +++");
    
    std::string sig = b64decode(_sig);
    const uint8_t* sigArr = (uint8_t *)sig.data();
 
    std::string m = b64decode(_m);
    const uint8_t* mArr = (uint8_t *)m.data();

    std::string pk = b64decode(_pk);
    const uint8_t* pkArr = (uint8_t *)pk.data();

    if (_ctx.empty()) {
        if (_ml_dsa_version == "3") {
    	      return pqcrystals_dilithium3_ref_verify(sigArr, sig.length(), mArr, m.length(), NULL, 0, pkArr);
        } else if (_ml_dsa_version == "5") {
    	      return pqcrystals_dilithium5_ref_verify(sigArr, sig.length(), mArr, m.length(), NULL, 0, pkArr);
        } else {
    	      return pqcrystals_dilithium2_ref_verify(sigArr, sig.length(), mArr, m.length(), NULL, 0, pkArr);
        }
    }

    std::string ctx = b64decode(_ctx);
    uint8_t* ctxArr = (uint8_t *)ctx.data();

    if (_ml_dsa_version == "3") {
        return pqcrystals_dilithium3_ref_verify(sigArr, sig.length(), mArr, m.length(), ctxArr, ctx.length(), pkArr);
    } else if (_ml_dsa_version == "5") {
        return pqcrystals_dilithium5_ref_verify(sigArr, sig.length(), mArr, m.length(), ctxArr, ctx.length(), pkArr);
    } else {
        return pqcrystals_dilithium2_ref_verify(sigArr, sig.length(), mArr, m.length(), ctxArr, ctx.length(), pkArr);
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
