#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "absl/debugging/failure_signal_handler.h"
#include "absl/debugging/symbolize.h"

#include <totp/totp.hpp>
#include <string>

void totpEmptyOrValidString(const std::string& str, long seconds) {
  auto totp = totp::GetTotpAt(str, seconds);
  if (!totp.empty()) {
    EXPECT_EQ(totp.size(), 6);
  }
}

FUZZ_TEST(totpFuzzTestSuite, totpEmptyOrValidString);
