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


add_executable(TOTP_test TOTP_test.cpp)
add_test(NAME TOTPTests COMMAND TOTP_test)

target_link_libraries(TOTP_test
    PRIVATE TOTP cotp Boost::ut OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(TOTP_test
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)
