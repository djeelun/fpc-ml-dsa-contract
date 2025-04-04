cmake_minimum_required(VERSION 3.5.1)
project(ML_DSA_CC)

include(FetchContent)

FetchContent_Declare(
  dilithium
  GIT_REPOSITORY https://github.com/pq-crystals/dilithium.git
  GIT_TAG        master
)
FetchContent_MakeAvailable(dilithium)

set(DILITHIUM_DIR ${CMAKE_BINARY_DIR}/external/dilithium)

# Download the repository
FetchContent_MakeAvailable(dilithium)

if (NOT EXISTS ${DILITHIUM_DIR})
    file(COPY ${dilithium_SOURCE_DIR} DESTINATION ${DILITHIUM_DIR})
endif()

message(STATUS "Repository downloaded to: ${DILITHIUM_DIR}")

set(DILITHIUM_REF_DIR ${DILITHIUM_DIR}/dilithium-src/ref)
set(DILITHIUM_SOURCE_FILES 
    ${DILITHIUM_REF_DIR}/ntt.c
    ${DILITHIUM_REF_DIR}/packing.c
    ${DILITHIUM_REF_DIR}/poly.c
    ${DILITHIUM_REF_DIR}/polyvec.c
    ${DILITHIUM_REF_DIR}/reduce.c
    ${DILITHIUM_REF_DIR}/rounding.c
    # sign.c
    ${DILITHIUM_REF_DIR}/symmetric-shake.c
    ${DILITHIUM_REF_DIR}/fips202.c
)
set(CUSTOM_SIGN_PATH ${CMAKE_CURRENT_SOURCE_DIR}/custom_sign/sign.c)

# Build static libraries for each version of ml-dsa
add_library(pqcrystals_dilithium2_ref STATIC ${DILITHIUM_SOURCE_FILES} ${CUSTOM_SIGN_PATH})
target_compile_definitions(pqcrystals_dilithium2_ref PRIVATE DILITHIUM_MODE=2)
add_library(pqcrystals_dilithium3_ref STATIC ${DILITHIUM_SOURCE_FILES} ${CUSTOM_SIGN_PATH})
target_compile_definitions(pqcrystals_dilithium3_ref PRIVATE DILITHIUM_MODE=3)
add_library(pqcrystals_dilithium5_ref STATIC ${DILITHIUM_SOURCE_FILES} ${CUSTOM_SIGN_PATH})
target_compile_definitions(pqcrystals_dilithium5_ref PRIVATE DILITHIUM_MODE=5)
# Set the output directory for the static libraries
set_target_properties(pqcrystals_dilithium2_ref pqcrystals_dilithium3_ref pqcrystals_dilithium5_ref
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${DILITHIUM_REF_DIR}
)

# Source files for chaincode
set(SOURCE_FILES
    ml_dsa_cc.cpp
    verification.cpp
    tdue.cpp
    b64.cpp
)

# Include headers
include_directories(
    ${DILITHIUM_REF_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_CURRENT_SOURCE_DIR} # For tdue.h
)

# Defines target enclave
include($ENV{FPC_PATH}/ecc_enclave/enclave/CMakeLists-common-app-enclave.txt)

# Link static libraries to enclave
# NOTE: in case of error, try upgrading minimum required cmake version (at the top of this file)
target_link_libraries(enclave "-L${DILITHIUM_REF_DIR} -Wl,--start-group -Wl,-Bstatic -lpqcrystals_dilithium2_ref -lpqcrystals_dilithium3_ref -lpqcrystals_dilithium5_ref -Wl,--end-group")
