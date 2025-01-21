#include "shim.h"
#include "logging.h"
#include "hexutils.h"
#include <string>
#include <sstream>
#include <stddef.h>
#include <stdint.h>
#include <vector>
extern "C" {
    #include "randombytes.h"   
    #include "sign.h"
}

// Verify signature given public key, message, and signature
// Arguments are given as hex strings
int verifySig(std::string _sig, std::string _m, std::string _ctx, std::string _pk)
{
    LOG_DEBUG("ML_DSA_CC: +++ verifySig +++");
    
    std::vector<uint8_t> sig = hex_string_to_bytes(_sig); // from hexutils.h
    const uint8_t* sigArr = &sig[0];
 
    std::vector<uint8_t> m = hex_string_to_bytes(_m);
    const uint8_t* mArr = &m[0];

    std::vector<uint8_t> pk = hex_string_to_bytes(_pk);
    const uint8_t* pkArr = &pk[0];

    if (_ctx.empty()) {
    	return crypto_sign_verify(sigArr, sig.size(), mArr, m.size(), NULL, 0, pkArr);
    }

    std::vector<uint8_t> ctx = hex_string_to_bytes(_ctx);
    uint8_t* ctxArr = &ctx[0];
    
    return crypto_sign_verify(sigArr, sig.size(), mArr, m.size(), ctxArr, ctx.size(), pkArr);
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
    std::vector<std::string> params;
    get_func_and_params(function_name, params, ctx);
    // std::string asset_name = params[0];
    std::string result;

    if (function_name == "verifySig")
    {
        std::string sig = params[0];
        std::string msg = params[1];
        std::string ctx = params[2];
        std::string pubkey = params[3];
        const int is_valid = verifySig(sig, msg, ctx, pubkey);
        
        std::stringstream ss;
        
        if (is_valid == 0) {
            result = "SUCCESS: Signature is valid\n";
        } else { // is_valid == -1
            ss << "FAILURE: Signature is not valid " << std::to_string(is_valid) << '\n';
            result = ss.str();
        }
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
