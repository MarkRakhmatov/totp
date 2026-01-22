#include "totp/totp.hpp"
#include <cstdlib>
#include <totp/cotp.hpp>
#include <string>

namespace otp
{

void deleter(void* ptr) noexcept
{
    if (ptr == nullptr)
    {
        return;
    }

    free(ptr);
}

totp_guard getTOTP(const std::string& secret, long epochSeconds)
{
  cotp_error_t err{};
  char* result = get_totp_at(secret.c_str(), epochSeconds, DEFAULT_DIGITS, DEFAULT_PERIOD, SHA1, &err);
  if (err != cotp_error::NO_ERROR)
  {
    return {nullptr, &deleter};
  }

  return {result, &deleter};
}

}
