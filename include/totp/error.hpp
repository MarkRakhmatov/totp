#ifndef ERROR_HPP
#define ERROR_HPP
#include <cstdint>

namespace totp
{
  enum struct Error: std::uint8_t {
    NoError = 0,
    Valid,
    WcryptVersionMismatch,
    InvalidAlgo,
    InvalidDigits,
    InvalidPeriod,
    MemoryAllocationError,
    InvalidUserInput,
    MissingLeadingZero,
    InvalidCounter,
    WhmacError
  };
}

#endif  // ERROR_HPP
