#include "totp/totp.hpp"
#include <cotp.h>
#include <string>

namespace otp
{

void deleter(void* p) noexcept
{
    if (!p)
    {
        return;
    }

    return delete static_cast<char*>(p);
}

totp_guard getTOTP(const std::string& secret, long epochSeconds)
{
  cotp_error_t err{};
  char* result = get_totp_at(secret.c_str(), epochSeconds, 6, 30, SHA1, &err);
  if (err != cotp_error::NO_ERROR)
  {
    return totp_guard(nullptr, &deleter);
  }

  return totp_guard(result, &deleter);
}

}
