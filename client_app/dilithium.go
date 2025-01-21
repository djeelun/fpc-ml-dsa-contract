package main

import (
	"os"
	"bufio"

	fpc "github.com/hyperledger/fabric-private-chaincode/client_sdk/go/pkg/gateway"
	"github.com/hyperledger/fabric-private-chaincode/integration/client_sdk/go/utils"
	"github.com/hyperledger/fabric/common/flogging"
)

var logger = flogging.MustGetLogger("dilithium")

func main() {
	ccID := os.Getenv("CC_ID")
	logger.Infof("Use Chaincode ID: %v", ccID)

	channelID := os.Getenv("CHAN_ID")
	logger.Infof("Use channel: %v", channelID)

	// get network
	network, _ := utils.SetupNetwork(channelID)

	// Get FPC Contract
	contract := fpc.GetContract(network, ccID)

	dirPath := "/project/src/github.com/hyperledger/fabric-private-chaincode/samples/chaincode/dilithium/client_app/"
	sigPaths := [2]string{
		dirPath + "dummy_sig.txt",
		dirPath + "dummy_sig2.txt",
	}

	sigPathsErr := [2]string{
		dirPath + "dummy_sig_err.txt",
		dirPath + "dummy_sig_err2.txt",
	}
	
	for _, sigPath := range sigPaths {
	 	verifySig(sigPath, contract, false)
    	}
	for _, sigPath := range sigPathsErr {
		verifySig(sigPath, contract, true)
    	}
}

func verifySig(path string, contract fpc.Contract, expectFail bool) {
	logger.Infof("--> READING DATA FROM: %s", path)
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
	
	if len(stringsList) < 4 {
		logger.Fatal("Not enough parameters in signature text file")
	}
	
	signature := stringsList[0]
	message := stringsList[1]
	context := stringsList[2]
	pubkey := stringsList[3]

	// logger.Infof("signature: %s", signature);
	// logger.Infof("message: %s", message);
	// logger.Infof("context: %s", context);
	// logger.Infof("pubkey: %s", pubkey);

	// Invoke FPC Chaincode verifySig
	logger.Infof("--> Invoke FPC Chaincode: verifySig")
	if expectFail {
		logger.Infof("--> Failure expected next...")
	}
	result, err := contract.SubmitTransaction("verifySig", signature, message, context, pubkey)
	if err != nil {
		if expectFail {
			logger.Infof("--> Result: %v", err)
		} else {
			logger.Fatalf("Failed to Submit transaction: %v", err)
		}
	} else {
		logger.Infof("--> Result: %s", string(result))
	}
}
