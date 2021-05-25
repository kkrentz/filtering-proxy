cmake_minimum_required(VERSION 3.20)
project(filtering-proxy C CXX ASM)

option(WITH_HEAP "Enable dynamic memory allocation" ON)
option(WITH_TRAP "Enable the Tiny Remote Attestation Protocol (TRAP)" ON)

# check if SDK has been built and KEYSTONE_SDK_DIR configuration variable exists
if (NOT DEFINED KEYSTONE_SDK_DIR)
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR configuration variable to an installed SDK path")
endif()

if (NOT DEFINED LIBCOAP_INSTALL_PATH)
  message(FATAL_ERROR "Please set LIBCOAP_INSTALL_PATH")
endif()

if(WITH_TRAP)
  add_compile_definitions(WITH_TRAP=1)
else()
  add_compile_definitions(WITH_TRAP=0)
endif()

if(WITH_HEAP)
  add_compile_definitions(WITH_HEAP=1)
else()
  add_compile_definitions(WITH_HEAP=0)
endif()

include(${KEYSTONE_SDK_DIR}/cmake/macros.cmake)
include(ExternalProject)
find_package(Git REQUIRED)

use_riscv_toolchain($ENV{KEYSTONE_BITS})

# set paths to the libraries
cmake_path(SET KEYSTONE_LIB_HOST "${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a")
cmake_path(SET KEYSTONE_LIB_EDGE "${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a")
cmake_path(SET LIBCOAP "${LIBCOAP_INSTALL_PATH}/lib/libcoap-3.a")

# create a phony target "filtering-proxy"
add_custom_target("filtering-proxy")

set(common_src
  $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_aes_128.c
  $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_cbor.c
  $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_ccm_star.c
  $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_cose.c
  $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_list.c
  $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_sha_256.c
  $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng.c)
include_directories(common
  ${KEYSTONE_SDK_DIR}/include
  $ENV{KEYSTONE_SM}/src/libcoap/include)

set(eapp_bin filtering-eapp)
set(host_bin filtering-host-app)
set(package_name "filtering-proxy.ke")
set(package_script "./filtering-host-app filtering-eapp eyrie-rt loader.bin")

if(RISCV32)
  set(eyrie_plugins "freemem rv32")
else()
  set(eyrie_plugins "freemem")
endif()

# eapp

add_executable(${eapp_bin}
  ${common_src}
  tee/attestation_service.c
  tee/clock.c
  tee/coap.c
  tee/iot_client.c
  tee/iot_message.c
  tee/leaky-bucket.c
  tee/log.c
  tee/main.c
  tee/memory.c
  tee/ocall_dispatcher.c
  tee/oscore_ng_filter.c
  tee/registration.c
  tee/report.c
  $ENV{KEYSTONE_SDK}/src/app/encret.s
  $ENV{KEYSTONE_SDK}/src/app/string.c
  $ENV{KEYSTONE_SDK}/src/app/syscall.c)
if(NOT WITH_TRAP)
  target_sources(${eapp_bin}
    PRIVATE $ENV{KEYSTONE_SM}/src/libcoap/ext/micro-ecc/uECC.c
    PRIVATE $ENV{KEYSTONE_SM}/src/libcoap/src/oscore-ng/oscore_ng_bakery.c)
endif()
if(WITH_HEAP)
  target_sources(${eapp_bin} PRIVATE tee/tinyalloc/tinyalloc.c)
else()
  target_sources(${eapp_bin} PRIVATE tee/memb.c)
endif()

target_compile_definitions(${eapp_bin}
  PRIVATE LOG_LEVEL=1
  PRIVATE KEYSTONE_ENCLAVE=1)
target_link_libraries(${eapp_bin}
  -nostdlib
  -static
  "-T ${CMAKE_CURRENT_SOURCE_DIR}/tee/app.lds"
  ${KEYSTONE_LIB_EDGE})
target_include_directories(${eapp_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge)
target_compile_options(${eapp_bin} PRIVATE -Werror -Wall -Wextra -ffreestanding)
if(WITH_HEAP)
target_include_directories(${eapp_bin} PUBLIC tee/tinyalloc)
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
    PUBLIC $ENV{KEYSTONE_SM}/src/libcoap/ext/micro-ecc)
endif()

# host

add_executable(${host_bin}
  ${common_src}
  host_app/CoapServer.cpp
  host_app/EnclaveLogger.cpp
  host_app/main.cpp
  host_app/IotRequest.cpp
  host_app/Request.cpp
  host_app/Ocall.cpp
  host_app/OcallDispatcher.cpp
  host_app/OcallFactory.cpp
  host_app/PduFactory.cpp
  host_app/ProxiedRequest.cpp
  host_app/Referenceable.cpp
  host_app/RegistrantRequest.cpp
  host_app/Registration.cpp)

target_link_libraries(${host_bin}
  ${LIBCOAP} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include
  PUBLIC ${LIBCOAP_INSTALL_PATH}/include)
target_compile_options(${host_bin} PRIVATE -Werror -Wall -Wextra)

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
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
