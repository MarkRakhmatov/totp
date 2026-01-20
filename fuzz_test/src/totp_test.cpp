#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "absl/debugging/failure_signal_handler.h"
#include "absl/debugging/symbolize.h"

#include <totp/totp.hpp>
#include <string>

void totpNullptrOrNotEptyString(std::string s, long seconds) {
  auto totp = otp::getTOTP(s, seconds);
  if (totp != nullptr) {
    auto totpStr = std::string(totp.get());
    EXPECT_FALSE(totpStr.empty());
    EXPECT_EQ(totpStr.size(), 6);
  }
}

FUZZ_TEST(totpFuzzTestSuite, totpNullptrOrNotEptyString);
