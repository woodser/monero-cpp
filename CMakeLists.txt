list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

cmake_minimum_required(VERSION 3.4.1)

if (WIN32)
  add_definitions( "-D_GLIBCXX_USE_NANOSLEEP=1" ) # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
  add_definitions( "-DWIN32_LEAN_AND_MEAN" )
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wa,-mbig-obj -O2 -fPIC -std=c++14 -F/Library/Frameworks -pthread -lcrypto -lcrypt32 -lbcrypt") 
else()
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -std=c++14 -F/Library/Frameworks -pthread")
endif()

#SET(CMAKE_C_COMPILER /path/to/c/compiler)
#SET(CMAKE_CXX_COMPILER /path/to/cpp/compiler)
#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -std=c++14 -F/Library/Frameworks -pthread -fsanitize=address")    # TODO: way to enable sanitize?  get runtime error with this on

project(MoneroCppLibrary)

set(BUILD_LIBRARY ON)
set(BUILD_SAMPLE OFF)
set(BUILD_SCRATCHPAD OFF)
set(BUILD_TESTS OFF)

option(STATIC "Build using static libraries")
if(STATIC)
  if(WIN32)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .dll.a .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  endif()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DZMQ_STATIC")
endif()


###################
# monero-project
###################

set(MONERO_PROJECT "${CMAKE_SOURCE_DIR}/external/monero-project" CACHE STRING "Monero project source directory")
set(MONERO_PROJECT_SRC "${MONERO_PROJECT}/src")

set(EXTERNAL_LIBS_DIR ${CMAKE_SOURCE_DIR}/external-libs)
message(STATUS EXTERNAL_LIBS_DIR : ${EXTERNAL_LIBS_DIR})

####################
# Extra libraries
####################

if (APPLE)
  if (DEPENDS)
    list(APPEND EXTRA_LIBRARIES "-framework Foundation -framework IOKit -framework AppKit")
  else()
    find_library(COREFOUNDATION CoreFoundation)
    find_library(IOKIT IOKit)
    find_library(APPKIT AppKit)
    list(APPEND EXTRA_LIBRARIES ${IOKIT})
    list(APPEND EXTRA_LIBRARIES ${COREFOUNDATION})
    list(APPEND EXTRA_LIBRARIES ${APPKIT})
  endif()
endif()
if (WIN32)
  list(APPEND EXTRA_LIBRARIES setupapi)
endif()

message(STATUS EXTRA_LIBRARIES: ${EXTRA_LIBRARIES})

############
# Protobuf
############

if (NOT APPLE)
  include(FindProtobuf)
  find_package(Protobuf)
  message(STATUS "Protobuf lib: ${Protobuf_LIBRARY}, inc: ${Protobuf_INCLUDE_DIR}, protoc: ${Protobuf_PROTOC_EXECUTABLE}")
endif()

############
# LibUSB
############

find_library(usb_LIBRARY NAMES usb-1.0 libusb usb)
set(LibUSB_LIBRARIES ${usb_LIBRARY})

############
# Boost
############

set(Boost_NO_BOOST_CMAKE 1)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.58 QUIET REQUIRED COMPONENTS chrono date_time filesystem program_options regex serialization wserialization system thread)
if(Boost_FOUND)
  message(STATUS "Using Boost include dir at ${Boost_INCLUDE_DIR}")
  message(STATUS "Using Boost lib version: ${Boost_LIB_VERSION}")
  message(STATUS "Using Boost libs: ${Boost_LIBRARIES}")
endif()

############
# OpenSSL
############

if (APPLE AND NOT IOS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=default -std=c++14")
  if (NOT OPENSSL_ROOT_DIR)
      EXECUTE_PROCESS(COMMAND brew --prefix openssl
        OUTPUT_VARIABLE OPENSSL_ROOT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using OpenSSL found at ${OPENSSL_ROOT_DIR}")
  endif()
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  message(STATUS "Using OpenSSL include dir at ${OPENSSL_INCLUDE_DIR}")
  message(STATUS "Using OpenSSL libs: ${OPENSSL_LIBRARIES}")
endif()

if(STATIC AND NOT IOS)
  if(UNIX)
    set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARIES};${CMAKE_DL_LIBS};${CMAKE_THREAD_LIBS_INIT}")
  endif()
endif()

if (WIN32)
  list(APPEND OPENSSL_LIBRARIES ws2_32 crypt32 bcrypt)
endif()

############
# libsodium
############

find_library(SODIUM_LIBRARY sodium REQUIRED)
message(STATUS "Using libsodium library at ${SODIUM_LIBRARY}")

############
# HIDAPI
############

if(APPLE)
  include_directories(SYSTEM /usr/include/malloc)
  if(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
  endif()
endif()

find_package(HIDAPI REQUIRED)
message(STATUS "Using HIDAPI include dir at ${HIDAPI_INCLUDE_DIR}")
add_definitions(-DHAVE_HIDAPI)

#############
# Monero
#############

set(MONERO_PROJECT_BUILD "${MONERO_PROJECT}/build/release" CACHE STRING "Monero project build directory")
message(STATUS "Using monero-project build: " ${MONERO_PROJECT_BUILD})

list(APPEND CMAKE_MODULE_PATH "${MONERO_PROJECT}/cmake")

add_library(wallet STATIC IMPORTED)
set_target_properties(wallet PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/lib/libwallet.a)

# libwallet-crypto.a provides x86_64 asm for some wallet functions
if (EXISTS ${MONERO_PROJECT_BUILD}/src/crypto/wallet/libwallet-crypto.a)
  add_library(wallet_crypto_lib STATIC IMPORTED)
  set_target_properties(wallet_crypto_lib PROPERTIES IMPORTED_LOCATION
      ${MONERO_PROJECT_BUILD}/src/crypto/wallet/libwallet-crypto.a)
  set(wallet_crypto wallet_crypto_lib)
endif()

add_library(lmdb STATIC IMPORTED)
set_target_properties(lmdb PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/external/db_drivers/liblmdb/liblmdb.a)

add_library(epee STATIC IMPORTED)
set_target_properties(epee PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/contrib/epee/src/libepee.a)

############
# Unbound
############

find_package(Unbound)
if(NOT UNBOUND_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find libunbound")
else()
  message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIR}")
  if(UNBOUND_LIBRARIES)
    message(STATUS "Found libunbound library")
    if (WIN32)
      add_library(unbound STATIC IMPORTED)
    else()
      add_library(unbound SHARED IMPORTED)
    endif()
    set_target_properties(unbound PROPERTIES IMPORTED_LOCATION ${UNBOUND_LIBRARIES}) 
  else()
    message(FATAL_ERROR "Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
  endif()
endif()

add_library(rpc_base STATIC IMPORTED)
set_target_properties(rpc_base PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/rpc/librpc_base.a)

add_library(net STATIC IMPORTED)
set_target_properties(net PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/net/libnet.a)
    
add_library(hardforks STATIC IMPORTED)
set_target_properties(hardforks PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/hardforks/libhardforks.a)
    
add_library(easylogging STATIC IMPORTED)
set_target_properties(easylogging PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/external/easylogging++/libeasylogging.a)

add_library(cryptonote_core STATIC IMPORTED)
set_target_properties(cryptonote_core PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/cryptonote_core/libcryptonote_core.a)

add_library(cryptonote_basic STATIC IMPORTED)
set_target_properties(cryptonote_basic PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/cryptonote_basic/libcryptonote_basic.a)
    
add_library(cryptonote_format_utils_basic STATIC IMPORTED)
set_target_properties(cryptonote_format_utils_basic PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/cryptonote_basic/libcryptonote_format_utils_basic.a)

add_library(mnemonics STATIC IMPORTED)
set_target_properties(mnemonics PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/mnemonics/libmnemonics.a)

add_library(common STATIC IMPORTED)
set_target_properties(common PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/common/libcommon.a)

add_library(cncrypto STATIC IMPORTED)
set_target_properties(cncrypto PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/crypto/libcncrypto.a)

add_library(ringct STATIC IMPORTED)
set_target_properties(ringct PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/ringct/libringct.a)

add_library(ringct_basic STATIC IMPORTED)
set_target_properties(ringct_basic PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/ringct/libringct_basic.a)

add_library(blockchain_db STATIC IMPORTED)
set_target_properties(blockchain_db PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/blockchain_db/libblockchain_db.a)

add_library(blocks STATIC IMPORTED)
set_target_properties(blocks PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/blocks/libblocks.a)

add_library(checkpoints STATIC IMPORTED)
set_target_properties(checkpoints PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/checkpoints/libcheckpoints.a)

add_library(device STATIC IMPORTED)
set_target_properties(device PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/device/libdevice.a)
    
add_library(device_trezor STATIC IMPORTED)
set_target_properties(device_trezor PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/device_trezor/libdevice_trezor.a)

add_library(multisig STATIC IMPORTED)
set_target_properties(multisig PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/multisig/libmultisig.a)

add_library(version STATIC IMPORTED)
set_target_properties(version PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/src/libversion.a)
    
add_library(randomx STATIC IMPORTED)
set_target_properties(randomx PROPERTIES IMPORTED_LOCATION
    ${MONERO_PROJECT_BUILD}/external/randomx/librandomx.a)
    
########################
# Build c++ library
########################

set(
    LIBRARY_SRC_FILES
    src/utils/gen_utils.cpp
    src/utils/monero_utils.cpp
    src/daemon/monero_daemon_model.cpp
    src/daemon/monero_daemon.cpp
    src/wallet/monero_wallet_model.cpp
    src/wallet/monero_wallet_keys.cpp
    src/wallet/monero_wallet_full.cpp
)

if (BUILD_LIBRARY)

  if(STATIC)
      set(BUILD_SHARED_LIBS OFF)
  else()
      set(BUILD_SHARED_LIBS ON)
  endif()

  add_library(monero-cpp ${LIBRARY_SRC_FILES})

  target_include_directories(monero-cpp PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      src
      "${MONERO_PROJECT}/contrib/epee/include"
      "${MONERO_PROJECT}/external/"
      "${MONERO_PROJECT}/external/easylogging++"
      "${MONERO_PROJECT}/external/rapidjson/include"
      "${MONERO_PROJECT_SRC}/"
      "${MONERO_PROJECT_SRC}/wallet"
      "${MONERO_PROJECT_SRC}/wallet/api"
      "${MONERO_PROJECT_SRC}/hardforks"
      "${MONERO_PROJECT_SRC}/crypto"
      "${MONERO_PROJECT_SRC}/crypto/crypto_ops_builder/include/"
      ${Protobuf_INCLUDE_DIR}
      ${Boost_INCLUDE_DIR}
      ${OPENSSL_INCLUDE_DIR}
      external/libsodium/include/sodium
      external/openssl-sdk/include
      ${HIDAPI_INCLUDE_DIR}
      ${UNBOUND_INCLUDE_DIR}
  )
  
  target_link_libraries(monero-cpp
      wallet
      rpc_base
      net
      lmdb
      unbound
      easylogging
      cryptonote_core
      cryptonote_basic
      cryptonote_format_utils_basic
      mnemonics
      ringct
      ringct_basic
      common
      cncrypto
      blockchain_db
      blocks
      checkpoints
      device
      device_trezor
      multisig
      version
      randomx
      epee
      hardforks
      ${wallet_crypto}
      
      ${UNBOUND_LIBRARIES}
      ${Boost_LIBRARIES}
      ${Protobuf_LIBRARY}
      ${LibUSB_LIBRARIES}
      ${OPENSSL_LIBRARIES}
      ${SODIUM_LIBRARY}
      ${HIDAPI_LIBRARIES}
      ${EXTRA_LIBRARIES}
  )

if (WIN32)
    target_link_options(monero-cpp PUBLIC "-Wl,--enable-auto-import,--export-all-symbols")
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(monero-cpp PRIVATE "-z" "noexecstack")
endif()

  INSTALL(FILES src/daemon/monero_daemon.h
          src/daemon/monero_daemon_model.h
          DESTINATION include/daemon)
  INSTALL(FILES src/utils/gen_utils.h
          src/utils/monero_utils.h
          DESTINATION include/utils)
  INSTALL(FILES src/wallet/monero_wallet_full.h
          src/wallet/monero_wallet.h
          src/wallet/monero_wallet_keys.h
          src/wallet/monero_wallet_model.h
          DESTINATION include/wallet)
  INSTALL(TARGETS monero-cpp
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Development)
endif()

########################
# Build C++ sample Code
########################

if (BUILD_SAMPLE)
  set(SAMPLE_CODE_SRC_FILES test/sample_code.cpp)
  
  add_executable(sample_code ${LIBRARY_SRC_FILES} ${SAMPLE_CODE_SRC_FILES})

  target_include_directories(sample_code PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      src
      "${MONERO_PROJECT}/contrib/epee/include"
      "${MONERO_PROJECT}/external/"
      "${MONERO_PROJECT}/external/easylogging++"
      "${MONERO_PROJECT}/external/rapidjson/include"
      "${MONERO_PROJECT_SRC}/"
      "${MONERO_PROJECT_SRC}/wallet"
      "${MONERO_PROJECT_SRC}/wallet/api"
      "${MONERO_PROJECT_SRC}/hardforks"
      "${MONERO_PROJECT_SRC}/crypto"
      "${MONERO_PROJECT_SRC}/crypto/crypto_ops_builder/include/"
      ${Protobuf_INCLUDE_DIR}
      ${Boost_INCLUDE_DIR}
      ${OPENSSL_INCLUDE_DIR}
      external/libsodium/include/sodium
      external/openssl-sdk/include
      ${HIDAPI_INCLUDE_DIR}
      ${UNBOUND_INCLUDE_DIR}
  )
  
  target_link_libraries(sample_code
      wallet
      rpc_base
      net
      lmdb
      easylogging
      cryptonote_core
      cryptonote_basic
      cryptonote_format_utils_basic
      mnemonics
      ringct
      ringct_basic
      common
      cncrypto
      blockchain_db
      blocks
      checkpoints
      device
      device_trezor
      multisig
      version
      randomx
      epee
      hardforks
      ${wallet_crypto}

      ${UNBOUND_LIBRARIES}
      ${Boost_LIBRARIES}
      ${Protobuf_LIBRARY}
      ${LibUSB_LIBRARIES}
      ${OPENSSL_LIBRARIES}
      ${SODIUM_LIBRARY}
      ${HIDAPI_LIBRARIES}
      ${EXTRA_LIBRARIES}
  )
  if (NOT WIN32)
    target_link_libraries(sample_code dl)
  endif()
endif()

########################
# Build C++ scratchpad
########################

if (BUILD_SCRATCHPAD)
  set(SCRATCHPAD_SRC_FILES test/scratchpad.cpp)
  
  add_executable(scratchpad ${LIBRARY_SRC_FILES} ${SCRATCHPAD_SRC_FILES})

  target_include_directories(scratchpad PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      src
      "${MONERO_PROJECT}/contrib/epee/include"
      "${MONERO_PROJECT}/external/"
      "${MONERO_PROJECT}/external/easylogging++"
      "${MONERO_PROJECT}/external/rapidjson/include"
      "${MONERO_PROJECT_SRC}/"
      "${MONERO_PROJECT_SRC}/wallet"
      "${MONERO_PROJECT_SRC}/wallet/api"
      "${MONERO_PROJECT_SRC}/hardforks"
      "${MONERO_PROJECT_SRC}/crypto"
      "${MONERO_PROJECT_SRC}/crypto/crypto_ops_builder/include/"
      ${Protobuf_INCLUDE_DIR}
      ${Boost_INCLUDE_DIR}
      ${OPENSSL_INCLUDE_DIR}
      external/libsodium/include/sodium
      external/openssl-sdk/include
      ${HIDAPI_INCLUDE_DIR}
      ${UNBOUND_INCLUDE_DIR}
  )
  
  target_link_libraries(scratchpad
      wallet
      rpc_base
      net
      lmdb
      easylogging
      cryptonote_core
      cryptonote_basic
      cryptonote_format_utils_basic
      mnemonics
      ringct
      ringct_basic
      common
      cncrypto
      blockchain_db
      blocks
      checkpoints
      device
      device_trezor
      multisig
      version
      randomx
      epee
      hardforks
      ${wallet_crypto}
      
      ${UNBOUND_LIBRARIES}
      ${Boost_LIBRARIES}
      ${Protobuf_LIBRARY}
      ${LibUSB_LIBRARIES}
      ${OPENSSL_LIBRARIES}
      ${SODIUM_LIBRARY}
      ${HIDAPI_LIBRARIES}
      ${EXTRA_LIBRARIES}
  )
  if (NOT WIN32)
    target_link_libraries(scratchpad dl)
  endif()
endif()

########################
# Build C++ tests
########################

if (BUILD_TESTS)
  set(TEST_SRC_FILES test/monero_tests.cpp)
  
  add_executable(monero_tests ${LIBRARY_SRC_FILES} ${TEST_SRC_FILES})

  target_include_directories(monero_tests PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      src
      "${MONERO_PROJECT}/contrib/epee/include"
      "${MONERO_PROJECT}/external/"
      "${MONERO_PROJECT}/external/easylogging++"
      "${MONERO_PROJECT}/external/rapidjson/include"
      "${MONERO_PROJECT_SRC}/"
      "${MONERO_PROJECT_SRC}/wallet"
      "${MONERO_PROJECT_SRC}/wallet/api"
      "${MONERO_PROJECT_SRC}/hardforks"
      "${MONERO_PROJECT_SRC}/crypto"
      "${MONERO_PROJECT_SRC}/crypto/crypto_ops_builder/include/"
      ${Protobuf_INCLUDE_DIR}
      ${Boost_INCLUDE_DIR}
      ${OPENSSL_INCLUDE_DIR}
      external/libsodium/include/sodium
      external/openssl-sdk/include
      ${HIDAPI_INCLUDE_DIR}
      ${UNBOUND_INCLUDE_DIR}
  )
  
  target_link_libraries(monero_tests
      wallet
      rpc_base
      net
      lmdb
      easylogging
      cryptonote_core
      cryptonote_basic
      cryptonote_format_utils_basic
      mnemonics
      ringct
      ringct_basic
      common
      cncrypto
      blockchain_db
      blocks
      checkpoints
      device
      device_trezor
      multisig
      version
      randomx
      epee
      hardforks
      ${wallet_crypto}
      
      ${UNBOUND_LIBRARIES}
      ${Boost_LIBRARIES}
      ${Protobuf_LIBRARY}
      ${LibUSB_LIBRARIES}
      ${OPENSSL_LIBRARIES}
      ${SODIUM_LIBRARY}
      ${HIDAPI_LIBRARIES}
      ${EXTRA_LIBRARIES}
  )
  if (NOT WIN32)
    target_link_libraries(monero_tests dl)
  endif()
endif()
