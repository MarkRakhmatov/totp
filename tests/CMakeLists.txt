cmake_minimum_required(VERSION 3.28)

project(TOTPTests)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIGURATION>")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIGURATION>")

set(CMAKE_CXX_STANDARD 20)

CPMAddPackage(
  NAME ut
  GIT_REPOSITORY https://github.com/boost-ext/ut.git
  GIT_TAG v2.3.1
)


add_executable(totp_test totp_test.cpp)
add_test(NAME totpTests COMMAND totp_test)

target_link_libraries(totp_test
    PRIVATE TOTP cotp Boost::ut OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(totp_test
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)
