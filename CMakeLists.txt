cmake_minimum_required(VERSION 3.10)
project(filtering-proxy C CXX ASM)

option(WITH_HEAP "Enable dynamic memory allocation" ON)
option(WITH_TRAP "Enable FHMQV-C-based remote attestation" ON)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{LIBCOAP_DIR})
  message(FATAL_ERROR "Please set LIBCOAP_DIR environment variable to an installed SDK path")
endif()
set(LIBCOAP_DIR $ENV{LIBCOAP_DIR})

if(WITH_TRAP)
  add_compile_definitions(WITH_TRAP=1)
else()
  add_compile_definitions(WITH_TRAP=0)
  if(NOT DEFINED ENV{SM_DIR})
    message(FATAL_ERROR "Please set SM_DIR")
  endif()
  set(SM_DIR $ENV{SM_DIR})
endif()

if(WITH_HEAP)
  add_compile_definitions(WITH_HEAP=1)
else()
  add_compile_definitions(WITH_HEAP=0)
endif()

include(${KEYSTONE_SDK_DIR}/cmake/macros.cmake)
include(ExternalProject)
find_package(Git REQUIRED)

if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
else()
  message(STATUS "riscv64")
  set(BITS 64)
endif()
use_riscv_toolchain(${BITS})

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)
set(LIBCOAP ${LIBCOAP_DIR}/lib/libcoap-3.a)

# create a phony target "filtering-proxy"
add_custom_target("filtering-proxy")

set(common_src common/aes-128.c
  common/cbor.c
  common/ccm-star.c
  common/cose.c
  common/list.c
  common/oscore_ng.c
  common/report.c
  common/sha-256.c)

set(eapp_bin filtering-eapp)
set(eapp_src filtering_enclave/attestation_service.c
  filtering_enclave/clock.c
  filtering_enclave/coap.c
  filtering_enclave/filtering_enclave.c
  filtering_enclave/ocall_dispatcher.c
  filtering_enclave/iot_client.c
  filtering_enclave/leaky-bucket.c
  filtering_enclave/log.c
  filtering_enclave/memory.c
  filtering_enclave/oscore_ng_filter.c
  filtering_enclave/iot_message.c
  filtering_enclave/registration.c)
if(NOT WITH_TRAP)
  list(APPEND eapp_src ${SM_DIR}/src/micro-ecc/uECC.c)
endif()
if(WITH_HEAP)
  list(APPEND eapp_src filtering_enclave/tinyalloc/tinyalloc.c)
else()
  list(APPEND eapp_src filtering_enclave/memb.c)
endif()
set(host_bin filtering-host-app)
set(host_src filtering_host_app/CoapServer.cpp
  filtering_host_app/EnclaveLogger.cpp
  filtering_host_app/filtering_host_app.cpp
  filtering_host_app/IotRequest.cpp
  filtering_host_app/Request.cpp
  filtering_host_app/Ocall.cpp
  common/oscore_ng.c
  filtering_host_app/OcallDispatcher.cpp
  filtering_host_app/OcallFactory.cpp
  filtering_host_app/PduFactory.cpp
  filtering_host_app/ProxiedRequest.cpp
  filtering_host_app/Referenceable.cpp
  filtering_host_app/Registration.cpp)
set(package_name "filtering-proxy.ke")
set(package_script "./filtering-host-app filtering-eapp eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem rv32")
else()
  set(eyrie_plugins "freemem")
endif()

# eapp

add_executable(${eapp_bin} ${common_src} ${eapp_src})
target_compile_definitions(${eapp_bin}
  PRIVATE LOG_LEVEL=1
  PRIVATE uECC_BYTES=32
  PRIVATE KEYSTONE_ENCLAVE=1)
target_link_libraries(${eapp_bin}
  -nostdlib
  -static
  "-T ${CMAKE_CURRENT_SOURCE_DIR}/filtering_enclave/app.lds"
  ${KEYSTONE_LIB_EAPP}
  ${KEYSTONE_LIB_EDGE})
target_include_directories(${eapp_bin}
  PUBLIC common
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge)
target_compile_options(${eapp_bin} PRIVATE -Werror -Wall -Wextra -ffreestanding)

if(WITH_HEAP)
target_include_directories(${eapp_bin} PUBLIC filtering_enclave/tinyalloc)
endif()

if(NOT WITH_TRAP)
  target_compile_definitions(${eapp_bin}
    PRIVATE uECC_CURVE=uECC_secp256r1
    PRIVATE uECC_SUPPORTS_secp160r1=0
    PRIVATE uECC_SUPPORTS_secp192r1=0
    PRIVATE uECC_SUPPORTS_secp224r1=0
    PRIVATE uECC_SUPPORTS_secp256r1=1
    PRIVATE uECC_SUPPORTS_secp256k1=0
    PRIVATE uECC_ENABLE_VLI_API=1)
  target_include_directories(${eapp_bin}
    PUBLIC ${SM_DIR}/src/micro-ecc)
endif()

# host

add_executable(${host_bin} ${common_src} ${host_src})
target_compile_definitions(${host_bin}
  PRIVATE uECC_BYTES=32)
target_link_libraries(${host_bin}
  ${LIBCOAP} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_include_directories(${host_bin}
  PUBLIC common
  PUBLIC ${KEYSTONE_SDK_DIR}/include
  PUBLIC ${LIBCOAP_DIR}/include)
target_compile_options(${host_bin} PRIVATE -Werror -Wall -Wextra)

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(filtering-proxy ${eapp_bin}-package)
