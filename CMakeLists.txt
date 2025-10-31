cmake_minimum_required(VERSION 3.16)

project(totp LANGUAGES CXX VERSION 0.1.0)

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
FetchContent_GetProperties(openssl BINARY_DIR OPENSSL_BUILD)
message("OPENSSL_BUILD: ${OPENSSL_BUILD}")
message("OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")

# override env to avoid using of system openssl
set(ENV{OPENSSL_INCLUDE_DIR} "${OPENSSL_INCLUDE_DIR}/include")
set(ENV{OPENSSL_LIB_DIR} "${OPENSSL_BUILD}")

CPMAddPackage(
  NAME cotp
  GITHUB_REPOSITORY "paolostivanin/libcotp"
  GIT_TAG v3.1.1
  OPTIONS
    "HMAC_WRAPPER openssl"
    "BUILD_SHARED_LIBS OFF"
)

FetchContent_GetProperties(cotp SOURCE_DIR COTP_SRC)
message("COTP_SRC: ${COTP_SRC}")

add_library(totp STATIC
  src/totp.cpp
  src/totp.h
)
# TODO exclude openssl path
set(CMAKE_SYSTEM_IGNORE_PATH "/usr/include/openssl")

target_include_directories(totp
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>

  PRIVATE "${COTP_SRC}/src"
)

target_compile_definitions(totp PRIVATE TOTP_LIBRARY)

add_subdirectory(tests)

set(ConfigPackageLocation lib/cmake/totp)

install(
  TARGETS totp
  EXPORT totpTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib

)

install(FILES src/totp.h DESTINATION include)

install(EXPORT totpTargets
  FILE totp.cmake
  DESTINATION lib/cmake/totp
)

include(CMakePackageConfigHelpers)
# generate the config file that is includes the exports
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/totpConfig.cmake"
  INSTALL_DESTINATION "lib/cmake/totp"
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
  )

# generate the version file for the config file
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/totpConfigVersion.cmake"
  VERSION "${totp_VERSION_MAJOR}.${totp_VERSION_MINOR}"
  COMPATIBILITY AnyNewerVersion
)
