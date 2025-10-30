#include "TOTP.h"

#include <cotp.h>

#include <chrono>

namespace otp
{

using namespace std::chrono_literals;
using namespace std::chrono;

void deleter(void* p) noexcept
{
    if (!p)
    {
        return;
    }

    return free(p);
}

totp_guard getTOTP(const std::string& secret)
{
    auto date = year_month_day(2020y, January, 1d);
    std::chrono::sys_days timestamp_days = date;
    auto epoch_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        timestamp_days.time_since_epoch()
    ).count();

    cotp_error_t err{};
    char* result = get_totp_at(secret.c_str(), epoch_seconds, 6, 30, SHA1, &err);
    if (err != cotp_error::NO_ERROR)
    {
        return totp_guard(nullptr, &deleter);
    }

    return totp_guard(result, &deleter);
}

}
