#include <doctest/doctest.h>
#include <totp/totp.hpp>

#include <string>

TEST_CASE("totp") {
    auto totp = otp::getTOTP("IO3SKWXDGBFTDDJUGPPJA3KEQAKTGLCV");
    CHECK(totp.get());
    CHECK(std::string("700709") == std::string(totp.get()));
}
