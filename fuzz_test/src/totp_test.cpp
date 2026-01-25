#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "absl/debugging/failure_signal_handler.h"
#include "absl/debugging/symbolize.h"

#include <totp/totp.hpp>
#include <string>

void totpEmptyOrValidString(std::string s, long seconds) {
  auto totp = otp::getTOTP(s, seconds);
  if (!totp.empty()) {
    EXPECT_EQ(totp.size(), 6);
  }
}

FUZZ_TEST(totpFuzzTestSuite, totpEmptyOrValidString);
