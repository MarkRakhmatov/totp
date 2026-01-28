#pragma once
#include <cstdint>
#include <string>
#include <expected>
#include "totp/Error.hpp"

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
    explicit constexpr Strong(T value) : value(value) {}
    T value;
  };

  using Counter = Strong<long long, struct CounterTag>;
  using DigitsCount = Strong<int, struct DigitsTag>;
  using Period = Strong<int, struct PersiodTag>;

  constexpr DigitsCount gDefaultDigits(6);
  constexpr Period gDefaultPeriod(30);

  std::expected<std::string, Error> GetHOTP(
      const char   *base32EncodedSecret,
      Counter counter,
      DigitsCount digits,
      SHA shaAlgo);

  std::expected<std::string, Error> GetTotp(
      const char *base32EncodedSecret,
      DigitsCount digits,
      Period period,
      SHA shaAlgo=SHA::SHA1);

  std::expected<std::string, Error> GetTotpAt(
      const char *base32EncodedSecret,
      long long time,
      DigitsCount digits=gDefaultDigits,
      Period period=gDefaultPeriod,
      SHA shaAlgo=SHA::SHA1);

  std::expected<int64_t, Error>  TotpToInt(const std::string& otp);
}
