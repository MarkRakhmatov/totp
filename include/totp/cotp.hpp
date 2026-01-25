#pragma once
#include <cstdint>
#include <string>
#include "totp/error.hpp"

namespace otp
{

  enum struct SHA: std::uint8_t {
    SHA1 = 0,
    SHA256 = 1,
    SHA512 = 2
  };

  using uchar = unsigned char;

  template <class T, class Tag>
  struct Strong {
    explicit Strong(T v) : value(v) {}
    T value;
  };

  using Counter = Strong<long long, struct CounterTag>;
  using DigitsCount = Strong<int, struct DigitsTag>;
  using Period = Strong<int, struct PersiodTag>;

  bool     is_string_valid_b32 (const char *user_data);

  std::string get_hotp          (const char   *base32_encoded_secret,
                              Counter          counter,
                              DigitsCount           digits,
                              SHA           sha_algo,
                              error *err_code);

  std::string get_totp          (const char   *base32_encoded_secret,
                              DigitsCount           digits,
                              Period           period,
                              SHA           sha_algo,
                              error *err_code);

  std::string get_totp_at       (const char   *base32_encoded_secret,
                              long long          time,
                              DigitsCount           digits,
                              Period           period,
                              SHA           sha_algo,
                              error *err_code);

  int64_t  otp_to_int        (const char   *otp,
                              error *err_code);

}
