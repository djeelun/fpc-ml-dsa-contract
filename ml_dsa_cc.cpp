#include "shim.h"
#include "logging.h"
#include "tdue.h"
#include "verification.h"
#include <string>
#include <sstream>
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <numeric>

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
    else if (function_name == "putCipher") {
        std::string cipherId = params[0];
        std::string cipherB64 = params[1];

        int err = putCipher(cipherB64, cipherId, ctx);
        if (err) {
            result = "FAILURE: FAILED TO PUT CIPHER ON LEDGER";
        } else {
            result = "SUCCESS: Successfully put ciphertext on ledger";
        }
    }
    else if (function_name == "getCipher") {
        std::string cipherId = params[0];

        std::string cipherB64(sizeof(int) * BLEN, '\0');
        int err = getCipher(cipherId, ctx, cipherB64);
        if (err) {
            result = "FAILURE: FAILED TO RETRIEVE CIPHER FROM LEDGER";
        } else {
            result = cipherB64;
        }
    }
    else if (function_name == "updateCipher") {
        std::string cipherId = params[0];
        std::string keySwitchMat = params[1];
        std::string b0prime = params[2];
        const std::string err = updateCipher(cipherId, keySwitchMat, b0prime, ctx); // from tdue.h

        result = err;
        
        /*if (err) {*/
        /*    std::stringstream ss;*/
        /*    ss << "FAILURE: Signature is not valid " << std::to_string(!err) << '\n';*/
        /*    result = ss.str();*/
        /*} else { */
        /*    result = "SUCCESS: Signature is valid\n";*/
        /*}*/
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
