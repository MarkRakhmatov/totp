#include "totp/totp.hpp"
#include <totp/cotp.hpp>
#include <string>
#include "totp/error.hpp"

namespace otp
{
  constexpr int DEFAULT_DIGITS = 6;
  constexpr int DEFAULT_PERIOD = 30;

std::string getTOTP(const std::string& secret, long epochSeconds)
{
  error err{};
  const auto& result = get_totp_at(secret.c_str(), epochSeconds, DigitsCount(DEFAULT_DIGITS), Period(DEFAULT_PERIOD), SHA::SHA1, &err);
  if (err != error::NO_ERROR)
  {
    return {};
  }

  return result;
}

}
