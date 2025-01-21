#!/usr/bin/env bash

if [[ -z "${FPC_PATH}" ]]; then
  echo "Error: FPC_PATH not set"; exit 1
fi

FABRIC_CFG_PATH="${FPC_PATH}/integration/config"
FABRIC_SCRIPTDIR="${FPC_PATH}/fabric/bin/"

. ${FABRIC_SCRIPTDIR}/lib/common_utils.sh
. ${FABRIC_SCRIPTDIR}/lib/common_ledger.sh

# this is the path points to FPC chaincode binary
CC_PATH=${FPC_PATH}/samples/chaincode/fpc-ml-dsa-contract/_build/lib/

CC_ID=ml_dsa_test
CC_VER="$(cat ${CC_PATH}/mrenclave)"
CC_EP="OR('SampleOrg.member')"
CC_SEQ="1"

run_test() {
    # install *mldsa* chaincode
    # input:  CC_ID:chaincode name; CC_VER:chaincode version;
    #         CC_PATH:path to build artifacts
    say "- install ml-dsa chaincode"
    PKG=/tmp/${CC_ID}.tar.gz
    ${PEER_CMD} lifecycle chaincode package --lang fpc-c --label ${CC_ID} --path ${CC_PATH} ${PKG}
    ${PEER_CMD} lifecycle chaincode install ${PKG}

    PKG_ID=$(${PEER_CMD} lifecycle chaincode queryinstalled | awk "/Package ID: ${CC_ID}/{print}" | sed -n 's/^Package ID: //; s/, Label:.*$//;p')

    ${PEER_CMD} lifecycle chaincode approveformyorg -o ${ORDERER_ADDR} -C ${CHAN_ID} --package-id ${PKG_ID} --name ${CC_ID} --version ${CC_VER} --sequence ${CC_SEQ} --signature-policy ${CC_EP}
    ${PEER_CMD} lifecycle chaincode checkcommitreadiness -C ${CHAN_ID} --name ${CC_ID} --version ${CC_VER} --sequence ${CC_SEQ} --signature-policy ${CC_EP}
    ${PEER_CMD} lifecycle chaincode commit -o ${ORDERER_ADDR} -C ${CHAN_ID} --name ${CC_ID} --version ${CC_VER} --sequence ${CC_SEQ} --signature-policy ${CC_EP}

    # create an FPC chaincode enclave
    ${PEER_CMD} lifecycle chaincode initEnclave -o ${ORDERER_ADDR} --peerAddresses "localhost:7051" --name ${CC_ID}
    
    # verify signature of proof
    # run test with go app
    say "- interact with the FPC chaincode using our client app"
    export CC_ID
    export CHAN_ID
    go run client_app/ml_dsa.go
}

trap ledger_shutdown EXIT

say "Setup ledger ..."
ledger_init

para
say "Run mldsa test ..."
run_test

para
say "Shutdown ledger ..."
ledger_shutdown

yell "ML_DSA test PASSED"

exit 0
