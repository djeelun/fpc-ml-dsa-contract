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

# Download the repository without building it
FetchContent_MakeAvailable(dilithium)

if (NOT EXISTS ${DILITHIUM_DIR})
    file(COPY ${dilithium_SOURCE_DIR} DESTINATION ${DILITHIUM_DIR})
endif()

message(STATUS "Repository downloaded to: ${DILITHIUM_DIR}")

# Set C flags for dilithium library
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDILITHIUM_MODE=2")

set(DILITHIUM_REF_DIR ${DILITHIUM_DIR}/dilithium-src/ref)

# Instead of randombytes.c provided by the library, we'll use our own randombytes.c
# This has to do with restrictions on I/O and randomness in SGX enclaves

set(SOURCE_FILES
    ml_dsa_cc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/hexutils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/randombytes/randombytes.c
    ${DILITHIUM_REF_DIR}/fips202.c
    ${DILITHIUM_REF_DIR}/ntt.c
    ${DILITHIUM_REF_DIR}/packing.c
    ${DILITHIUM_REF_DIR}/poly.c
    ${DILITHIUM_REF_DIR}/polyvec.c
    ${DILITHIUM_REF_DIR}/reduce.c
    ${DILITHIUM_REF_DIR}/rounding.c
    ${DILITHIUM_REF_DIR}/sign.c
    ${DILITHIUM_REF_DIR}/symmetric-shake.c
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer -DDILITHIUM_MODE=2")

include_directories(
    ${DILITHIUM_REF_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

include($ENV{FPC_PATH}/ecc_enclave/enclave/CMakeLists-common-app-enclave.txt)
