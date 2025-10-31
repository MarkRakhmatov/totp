#include <boost/ut.hpp>
#include "totp.h"

int main() {
  using namespace boost::ut;

  "verify_totp"_test = [] {
      auto totp = otp::getTOTP("IO3SKWXDGBFTDDJUGPPJA3KEQAKTGLCV");
      expect(totp.get());
      expect(std::string("700709") == totp.get());
  };
}
