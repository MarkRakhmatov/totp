#pragma once
#include <cstdint>
#include <string>
#include <expected>
#include "totp/error.hpp"

namespace totp
{

  enum struct SHA: std::uint8_t {
    SHA1 = 0,
    SHA256 = 1,
    SHA512 = 2
  };

  using uchar = unsigned char;

  template <class T, class Tag>
  struct Strong {
    explicit constexpr Strong(T v) : value(v) {}
    T value;
  };

  using Counter = Strong<long long, struct CounterTag>;
  using DigitsCount = Strong<int, struct DigitsTag>;
  using Period = Strong<int, struct PersiodTag>;

  constexpr DigitsCount DEFAULT_DIGITS(6);
  constexpr Period DEFAULT_PERIOD(30);

  bool is_string_valid_b32(const char *user_data);

  std::expected<std::string, error> get_hotp(
      const char   *base32_encoded_secret,
      Counter counter,
      DigitsCount digits,
      SHA sha_algo);

  std::expected<std::string, error> get_totp(
      const char *base32_encoded_secret,
      DigitsCount digits,
      Period period,
      SHA sha_algo=SHA::SHA1);

  std::expected<std::string, error> get_totp_at(
      const char *base32_encoded_secret,
      long long time,
      DigitsCount digits=DEFAULT_DIGITS,
      Period period=DEFAULT_PERIOD,
      SHA sha_algo=SHA::SHA1);

  std::expected<int64_t, error>  otp_to_int(const std::string& otp);
}
