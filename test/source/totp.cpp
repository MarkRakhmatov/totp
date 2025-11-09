#include <doctest/doctest.h>
#include <totp/totp.hpp>

#include <string>
#include <chrono>

using namespace std::chrono_literals;
using namespace std::chrono;

TEST_CASE("totp") {
    auto date = year_month_day(2020y, January, 1d);
    std::chrono::sys_days timestamp_days = date;
    auto epoch_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                             timestamp_days.time_since_epoch()
                             ).count();
    CHECK(epoch_seconds == 1577836800);
    auto totp = otp::getTOTP("IO3SKWXDGBFTDDJUGPPJA3KEQAKTGLCV", static_cast<long>(epoch_seconds));
    CHECK(totp.get());
    CHECK(std::string("700709") == std::string(totp.get()));
}
