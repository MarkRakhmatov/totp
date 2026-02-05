#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "absl/debugging/failure_signal_handler.h"
#include "absl/debugging/symbolize.h"

#include <totp/totp.hpp>
#include <string>

void totpEmptyOrValidString(const std::string& str, long seconds) {
  auto totp = totp::getTotpAt(str.c_str(), seconds);
  if (totp.has_value()) {
    EXPECT_EQ(totp.value().size(), 6);
  }
}

FUZZ_TEST(totpFuzzTestSuite, totpEmptyOrValidString);
