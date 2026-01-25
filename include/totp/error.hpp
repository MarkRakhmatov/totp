#ifndef ERROR_HPP
#define ERROR_HPP
#include <cstdint>

namespace otp
{
  enum struct error: std::uint8_t {
    NO_ERROR = 0,
    VALID,
    WCRYPT_VERSION_MISMATCH,
    INVALID_ALGO,
    INVALID_DIGITS,
    INVALID_PERIOD,
    MEMORY_ALLOCATION_ERROR,
    INVALID_USER_INPUT,
    EMPTY_STRING,
    MISSING_LEADING_ZERO,
    INVALID_COUNTER,
    WHMAC_ERROR
  };
}

#endif  // ERROR_HPP
