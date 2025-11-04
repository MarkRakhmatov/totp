#include "totp/totp.hpp"
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

totp_guard getTOTP(const std::string&)
{
    // TODO remove hardcoded bulllshit after dependencies fix
    auto p = new char[7];
    p[0] = '7';
    p[1] = '0';
    p[2] = '0';
    p[3] = '7';
    p[4] = '0';
    p[5] = '9';
    p[6] = '\0';
    return totp_guard(p, &deleter);
}

}
