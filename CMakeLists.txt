cmake_minimum_required(VERSION 3.16)

project(TOTP LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(
  DOWNLOAD
  https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.40.8/CPM.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake
  EXPECTED_HASH SHA256=78ba32abdf798bc616bab7c73aac32a17bbd7b06ad9e26a6add69de8f3ae4791
)

include(${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake)

CPMAddPackage(
  NAME openssl-cmake
  GITHUB_REPOSITORY "jimmy-park/openssl-cmake"
  GIT_TAG 3.6.0
  OPTIONS
    "OPENSSL_CONFIGURE_OPTIONS no-shared\\\\;no-tests"
    "OPENSSL_CONFIGURE_VERBOSE ON"
)
FetchContent_GetProperties(openssl SOURCE_DIR OPENSSL_SRC)
message(STATUS "OPENSSL_SRC: ${OPENSSL_SRC}")

CPMAddPackage(
  NAME cotp
  GITHUB_REPOSITORY "paolostivanin/libcotp"
  GIT_TAG v3.1.1
  OPTIONS
    "HMAC_WRAPPER openssl"
    "BUILD_SHARED_LIBS OFF"
)

FetchContent_GetProperties(cotp SOURCE_DIR COTP_SRC)
message(STATUS "COTP_SRC: ${COTP_SRC}")

add_library(TOTP STATIC
  src/TOTP.cpp
  src/TOTP.h
)

target_include_directories(TOTP
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src"

  PRIVATE "${COTP_SRC}/src"
  PRIVATE "${OPENSSL_SRC}/include"
)

target_compile_definitions(TOTP PRIVATE TOTP_LIBRARY)

add_subdirectory(tests)


install(
  TARGETS TOTP
  ARCHIVE DESTINATION lib LIBRARY DESTINATION lib
)

install(FILES src/TOTP.h DESTINATION include)
