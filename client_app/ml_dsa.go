package main

import (
	"os"
	"bufio"
	"strings"

	fpc "github.com/hyperledger/fabric-private-chaincode/client_sdk/go/pkg/gateway"
	"github.com/hyperledger/fabric-private-chaincode/integration/client_sdk/go/utils"
	"github.com/hyperledger/fabric/common/flogging"
)

var logger = flogging.MustGetLogger("ml-dsa")
var dirPath = "/project/src/github.com/hyperledger/fabric-private-chaincode/samples/chaincode/fpc-ml-dsa-contract/client_app/"

func main() {
	ccID := os.Getenv("CC_ID")
	logger.Infof("Use Chaincode ID: %v", ccID)

	channelID := os.Getenv("CHAN_ID")
	logger.Infof("Use channel: %v", channelID)

	// get network
	network, _ := utils.SetupNetwork(channelID)

	// Get FPC Contract
	contract := fpc.GetContract(network, ccID)

  // Test valid and invalid signatures
	sigTxtsDir := dirPath + "sig_txts/"
	sigPaths := [2]string{
		"sig_good_44.txt",
		"sig_good_87.txt",
	}

	sigPathsErr := [3]string{
		"sig_corruptmsg_44.txt",
		"sig_corruptsig_44.txt",
		"sig_corruptpk_44.txt",
	}
	
	logger.Infof("--> ##### Test valid and invalid signatures #####")
	for _, sigPath := range sigPaths {
	 	verifySig(sigTxtsDir + sigPath, sigPath, contract, false)
  }
	for _, sigPath := range sigPathsErr {
		verifySig(sigTxtsDir + sigPath, sigPath, contract, true)
  }

  // Test storing signatures on chain
	logger.Infof("--> ##### Test storing signatures #####")
  storeSig(sigTxtsDir + sigPaths[0], contract)

  // Test updatable encryption
  logger.Infof("--> ##### Test updatable encryption #####")
  updateCipher(contract)
}

// Tests verifySig (for verifying ML-DSA signatures)
func verifySig(path string, fileName string, contract fpc.Contract, expectFail bool) {
  signature, message, context, pubkey, version := getValuesFromFile(path)

	// Invoke FPC Chaincode verifySig
	logger.Infof("--> Invoke FPC Chaincode: verifySig [" + fileName + "]")
	result, err := contract.EvaluateTransaction("verifySig", signature, message, context, pubkey, version)
	if err != nil {
		logger.Fatalf("Error: %v", err)
	} else {
		invokeSuccess := strings.HasPrefix(string(result), "SUCCESS")

		if (expectFail != invokeSuccess) {
			logger.Infof("Test passed successfully")
		} else {
			logger.Infof("Test failed: %s", string(result))
		}
	}
}

// Tests getVerificationResult and putVerificationResult
func storeSig(path string, contract fpc.Contract) {
  signature, message, context, pubkey, version := getValuesFromFile(path)

	// Get inexistent verification result
	logger.Infof("--> Invoke FPC Chaincode: getVerificationResult")
	result, err := contract.SubmitTransaction("getVerificationResult", signature)
	if err != nil {
    logger.Infof("--> Error: %v", err)
	} else {
		invokeSuccess := strings.HasPrefix(string(result), "KEY NOT FOUND")
		if invokeSuccess {
			logger.Infof("Test passed successfully")
		} else {
			logger.Infof("Test failed: %s", string(result))
		}
	}

	// Invoke FPC Chaincode verifySig
	logger.Infof("--> Invoke FPC Chaincode: putVerificationResult")
	result, err = contract.SubmitTransaction("putVerificationResult", signature, message, context, pubkey, version)
	if err != nil {
		logger.Infof("--> Error: %v", err)
	} else {
		invokeSuccess := strings.HasPrefix(string(result), "OK")
		if invokeSuccess {
			logger.Infof("Test passed successfully")
		} else {
			logger.Infof("Test failed: %s", string(result))
		}
	}

	// Get verification result of signature we just verified
	logger.Infof("--> Invoke FPC Chaincode: getVerificationResult")
	result, err = contract.SubmitTransaction("getVerificationResult", signature)
	if err != nil {
    logger.Infof("--> Result: %v", err)
	} else {
		invokeSuccess := strings.HasPrefix(string(result), "SUCCESS")
		if invokeSuccess {
			logger.Infof("Test passed successfully")
		} else {
			logger.Infof("Test failed: %s", string(result))
		}
	}
}

// Put cipher on ledger, get same cipher back to check if went correctly
// Then update cipher, get new cipher back to check if went correctly
func updateCipher(contract fpc.Contract) {
	tdueTxtsDir := dirPath + "tdue_txts/"
  cipherId := "myCipherId" // user-provided id?

	// put old ciphertext on ledger
  logger.Infof("--> Invoke FPC Chaincode: putCipher")
  ciphertext := readSingleLineFromFile(tdueTxtsDir + "tdue_old_ciphertext.txt")
  result, err := contract.SubmitTransaction("putCipher", cipherId, ciphertext) // Put ciphertext on ledger
  if err != nil {
    logger.Infof("--> Error: %v", err)
  } else {
		invokeSuccess := strings.HasPrefix(string(result), "SUCCESS")
		if invokeSuccess {
			logger.Infof("Test passed successfully")
		} else {
			logger.Infof("Test failed: %s", string(result))
		}
  }

	// get old ciphertext from ledger
  logger.Infof("--> Invoke FPC Chaincode: getCipher")
  result, err = contract.SubmitTransaction("getCipher", cipherId) // Get same cipher back
  if err != nil {
    logger.Infof("--> Error: %v", err)
  } else {
    if (string(result) == ciphertext) {
      logger.Infof("--> Result: SUCCESS %s", string(result))
    } else {
      logger.Infof("--> Result: FAILED, ciphertexts are not the same %s", string(result))
    }
  }

	// update ciphertext to new epoch
  keyswitchtoken := readSingleLineFromFile(tdueTxtsDir + "tdue_keyswitchmat.txt")
  b0prime := readSingleLineFromFile(tdueTxtsDir + "tdue_b0prime.txt")
  logger.Infof("--> Invoke FPC Chaincode: updateCipher")
  result, err = contract.SubmitTransaction("updateCipher", cipherId, keyswitchtoken, b0prime) // Replace with cipher id and update token
  if err != nil {
    logger.Infof("--> ERROR: %v", err)
  } else {
    logger.Infof("--> Result: %s", string(result))
  }

	// get new ciphertext from ledger
  newCiphertext := readSingleLineFromFile(tdueTxtsDir + "tdue_new_ciphertext.txt")
  logger.Infof("--> Invoke FPC Chaincode: getCipher")
  result, err = contract.SubmitTransaction("getCipher", cipherId) // Get same cipher back
  if err != nil {
    logger.Infof("--> ERROR: %v", err)
  } else {
    if (string(result) == newCiphertext) {
      logger.Infof("--> Success: %s", string(result))
    } else {
      logger.Infof("--> TEST FAILED, ciphertexts are not the same \n%s \n%s", string(result), string(newCiphertext))
    }
  }
}

func getValuesFromFile(path string) (string, string, string, string, string) {
	// logger.Infof("--> reading data from: %s", path)
	// Get signature etc. from file
	// with help from https://stackoverflow.com/a/16615559
	file, err := os.Open(path) 
	if err != nil {
		logger.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var stringsList []string
	for scanner.Scan() {
	// fmt.Println(scanner.Text())
		stringsList = append(stringsList, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
	 	logger.Fatal(err)
	}
	
	if len(stringsList) < 5 {
		logger.Fatal("Not enough parameters in signature text file")
	}
	
	signature := stringsList[0]
	message := stringsList[1]
	context := stringsList[2]
	pubkey := stringsList[3]
  version := stringsList[4]

	// logger.Infof("signature: %s", signature);
	// logger.Infof("message: %s", message);
	// logger.Infof("context: %s", context);
	// logger.Infof("pubkey: %s", pubkey);


  return signature, message, context, pubkey, version
}

func readSingleLineFromFile(path string) (string) {
	// logger.Infof("--> reading data from: %s", path)
	// with help from https://stackoverflow.com/a/16615559
	file, err := os.Open(path) 
	if err != nil {
		logger.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
  const maxCapacity int = 2000000  // your required line length
  buf := make([]byte, maxCapacity)
  scanner.Buffer(buf, maxCapacity)
	var stringsList []string
	for scanner.Scan() {
	// fmt.Println(scanner.Text())
		stringsList = append(stringsList, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
	 	logger.Fatal(err)
	}
	
	if len(stringsList) < 1 {
		logger.Fatal("Not enough parameters in signature text file")
	}

  return stringsList[0]
}
