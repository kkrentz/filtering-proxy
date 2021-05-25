cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

set(LIBCOAP_RISCV_DIR $ENV{LIBCOAP_RISCV_DIR})

if (NOT DEFINED ENV{SM_DIR})
  message(FATAL_ERROR "Please set SM_DIR")
endif()
set(SM_DIR $ENV{SM_DIR})

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
else()
  message(STATUS "riscv64")
  set(BITS 64)
endif()

use_riscv_toolchain(${BITS})

add_definitions(-DuECC_BYTES=32
  -DuECC_CURVE=uECC_secp256r1
  -DuECC_SUPPORTS_secp160r1=0
  -DuECC_SUPPORTS_secp192r1=0
  -DuECC_SUPPORTS_secp224r1=0
  -DuECC_SUPPORTS_secp256r1=1
  -DuECC_SUPPORTS_secp256k1=0
  -DuECC_ENABLE_VLI_API=1)

# export include directory
include_directories(common
  ${SM_DIR}/src/micro-ecc
  ${KEYSTONE_SDK_DIR}/include
  ${LIBCOAP_RISCV_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge)

# set paths to the libraries
set(LIBCOAP ${LIBCOAP_RISCV_DIR}/lib/libcoap-3.a)
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

# find program "makeself"
find_program(MAKESELF makeself)

# enclave
add_subdirectory(filtering_enclave)

set(host_bin filtering-host-app.riscv)
set(host_src
  ${SM_DIR}/src/micro-ecc/uECC.c
  common/aes-128.c
  common/cbor.c
  common/ccm-star.c
  common/cose.c
  common/oscore.c
  common/sha-256.c
  filtering_host_app/AttestationReport.cpp
  filtering_host_app/CoapServer.cpp
  filtering_host_app/EnclaveLogger.cpp
  filtering_host_app/filtering_host_app.cpp
  filtering_host_app/Ocall.cpp
  filtering_host_app/OcallDispatcher.cpp
  filtering_host_app/ProxiedRequest.cpp
  filtering_host_app/Registration.cpp)
set(eyrie_plugins "freemem")
set(package_name "filtering-host-app.ke")
set(package_script "./filtering-host-app.riscv")

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${LIBCOAP} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})

set(eyrie_files_to_copy eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  "master"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

add_keystone_package(package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} filtering_enclave/filtering_enclave.eapp_riscv ${host_bin})

add_dependencies(package ${eapp_bin}-eyrie)

