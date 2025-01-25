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
    ntt.c
    packing.c
    poly.c
    polyvec.c
    reduce.c
    rounding.c
    # sign.c
    symmetric-shake.c
)
set(CUSTOM_SIGN_PATH ${CMAKE_CURRENT_SOURCE_DIR}/custom_sign/sign.c)

# Build static libraries for each version of ml-dsa
add_custom_command(
    OUTPUT libpqcrystals_dilithium2_ref.a
    COMMAND cc -c -nostartfiles -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls
            -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer -DDILITHIUM_MODE=2
            ${DILITHIUM_SOURCE_FILES} ${CUSTOM_SIGN_PATH} fips202.c
    COMMAND ar -rcs libpqcrystals_dilithium2_ref.a ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o symmetric-shake.o fips202.o
    WORKING_DIRECTORY ${DILITHIUM_REF_DIR}
    COMMENT "Building static library: libpqcrystals_dilithium2_ref.a"
    VERBATIM
)
add_custom_command(
    OUTPUT libpqcrystals_dilithium3_ref.a
    COMMAND cc -c -nostartfiles -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls
            -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer -DDILITHIUM_MODE=3
            ${DILITHIUM_SOURCE_FILES} ${CUSTOM_SIGN_PATH} fips202.c
    COMMAND ar -rcs libpqcrystals_dilithium3_ref.a ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o symmetric-shake.o fips202.o
    WORKING_DIRECTORY ${DILITHIUM_REF_DIR}
    COMMENT "Building static library: libpqcrystals_dilithium3_ref.a"
    VERBATIM
)
add_custom_command(
    OUTPUT libpqcrystals_dilithium5_ref.a
    COMMAND cc -c -nostartfiles -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls
            -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer -DDILITHIUM_MODE=5
            ${DILITHIUM_SOURCE_FILES} ${CUSTOM_SIGN_PATH} fips202.c
    COMMAND ar -rcs libpqcrystals_dilithium5_ref.a ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o symmetric-shake.o fips202.o
    WORKING_DIRECTORY ${DILITHIUM_REF_DIR}
    COMMENT "Building static library: libpqcrystals_dilithium5_ref.a"
    VERBATIM
)

# This makes sure the libraries get built every time
add_custom_target(
  build_dilithium_lib ALL
  DEPENDS libpqcrystals_dilithium2_ref.a libpqcrystals_dilithium3_ref.a libpqcrystals_dilithium5_ref.a
)

# Source files for chaincode
set(SOURCE_FILES
    ml_dsa_cc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/hexutils.cpp
)

# Include headers
include_directories(
    ${DILITHIUM_REF_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

# Defines target enclave
include($ENV{FPC_PATH}/ecc_enclave/enclave/CMakeLists-common-app-enclave.txt)

# Link static libraries to enclave
# NOTE: in case of error, try upgrading minimum required cmake version (at the top of this file)
target_link_libraries(enclave "-L${DILITHIUM_REF_DIR} -Wl,--start-group -Wl,-Bstatic -lpqcrystals_dilithium2_ref -lpqcrystals_dilithium3_ref -lpqcrystals_dilithium5_ref -Wl,--end-group")
