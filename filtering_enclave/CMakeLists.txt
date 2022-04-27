add_executable(filtering_enclave.eapp_riscv
  attestation_service.c
  filtering_enclave.c
  filtering_ocall_client.c
  iot_client.c
  leaky-bucket.c
  list.c
  oscore_filter.c
  proxied_request.c
  registration.c
  ${SM_DIR}/src/micro-ecc/uECC.h
  ${SM_DIR}/src/micro-ecc/uECC.c
  ../common/aes-128.c
  ../common/cbor.c
  ../common/ccm-star.c
  ../common/cose.c
  ../common/oscore.c
  ../common/sha-256.c
  crypto.c)

include_directories(${KEYSTONE_SDK_DIR}/include/app)

target_link_libraries(filtering_enclave.eapp_riscv
  ${KEYSTONE_LIB_EAPP})

add_definitions(-DLOG_LEVEL=0)

set_target_properties(filtering_enclave.eapp_riscv
  PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")

target_compile_definitions(filtering_enclave.eapp_riscv PRIVATE KEYSTONE_ENCLAVE=1)
