#!/bin/bash

# To build all required FPC components run the following commands
# This does not run the integration tests as specified in the FPC guide
# which speeds things up considerably

cd $FPC_PATH
make docker
make build

